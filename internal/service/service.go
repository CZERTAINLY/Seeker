package service

import (
	"context"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/netip"
	"os"

	"github.com/CZERTAINLY/Seeker/internal/bom"
	"github.com/CZERTAINLY/Seeker/internal/gitleaks"
	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/CZERTAINLY/Seeker/internal/nmap"
	"github.com/CZERTAINLY/Seeker/internal/scan"
	"github.com/CZERTAINLY/Seeker/internal/walk"
	"github.com/CZERTAINLY/Seeker/internal/x509"
	"golang.org/x/sync/errgroup"
)

var detectors []scan.Detector

func init() {
	leaks, err := gitleaks.NewDetector()
	if err != nil {
		panic(err)
	}

	detectors = []scan.Detector{
		x509.Detector{},
		leaks,
	}
}

type Uploader interface {
	Upload(ctx context.Context, raw []byte) error
}

// Scanner is a component, which encapsulates the scan functionality and executes it.
type Scanner struct {
	filesystems iter.Seq2[walk.Entry, error]
	containers  iter.Seq2[walk.Entry, error]
	nmaps       []nmap.Scanner
	ips         []netip.Addr
}

func NewScanner(ctx context.Context, config model.Config) (Scanner, error) {
	if config.Version != 0 {
		return Scanner{}, fmt.Errorf("config version %d is not supported, expected 0", config.Version)
	}

	filesystems, err := filesystems(ctx, config.Filesystem)
	if err != nil {
		return Scanner{}, fmt.Errorf("initializing filesystem scan: %w", err)
	}

	containers, err := containers(ctx, config.Containers)
	if err != nil {
		return Scanner{}, fmt.Errorf("initializing containers scan: %w", err)
	}

	nmaps, ips, err := nmaps(ctx, config.Ports)
	if err != nil {
		return Scanner{}, fmt.Errorf("initializing port scan: %w", err)
	}

	return Scanner{
		filesystems: filesystems,
		containers:  containers,
		nmaps:       nmaps,
		ips:         ips,
	}, nil
}

func (s Scanner) Do(ctx context.Context, out io.Writer) error {
	g, ctx := errgroup.WithContext(ctx)

	b := bom.NewBuilder()
	detections := make(chan model.Detection)
	go func() {
		for d := range detections { // will be closed after g.Wait()
			b.AppendComponents(d.Components...)
			b.AppendDependencies(d.Dependencies...)
		}
	}()

	// TODO: configure a paralelism
	// filesystem scanners
	if s.filesystems != nil {
		scanner := scan.New(4, detectors)
		g.Go(func() error {
			goScan(ctx, scanner, s.filesystems, detections)
			return nil
		})
	}

	// containers scanners
	if s.containers != nil {
		scanner := scan.New(2, detectors)
		g.Go(func() error {
			goScan(ctx, scanner, s.containers, detections)
			return nil
		})
	}

	// nmap scans
	for _, ip := range s.ips {
		g.Go(func() error {
			for _, n := range s.nmaps {
				nmapScan(ctx, n, ip, detections)
			}
			return nil
		})
	}

	_ = g.Wait()
	close(detections)

	err := b.AsJSON(out)
	if err != nil {
		return fmt.Errorf("formatting BOM as JSON: %w", err)
	}
	return nil
}

func goScan(ctx context.Context, scanner *scan.Scan, seq iter.Seq2[walk.Entry, error], detections chan<- model.Detection) {
	for results, err := range scanner.Do(ctx, seq) {
		if err != nil {
			slog.DebugContext(ctx, "error on filesystem scan", "error", err)
			continue
		}
		for _, detection := range results {
			detections <- detection
		}
	}
}

func nmapScan(ctx context.Context, scanner nmap.Scanner, ip netip.Addr, detections chan<- model.Detection) {
	results, err := scanner.Detect(ctx, ip)
	if err != nil {
		slog.ErrorContext(ctx, "nmap scan failed", "error", err)
	}
	for _, d := range results {
		detections <- d
	}
}

func filesystems(ctx context.Context, cfg model.Filesystem) (iter.Seq2[walk.Entry, error], error) {
	var filesystems iter.Seq2[walk.Entry, error]
	if !cfg.Enabled {
		return filesystems, nil
	}

	paths := cfg.Paths
	if len(paths) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			return filesystems, fmt.Errorf("getting working directory: %w", err)
		}
		paths = []string{cwd}
	}

	roots := make([]*os.Root, 0, len(paths))
	for _, path := range paths {
		root, err := os.OpenRoot(path)
		if err != nil {
			return filesystems, fmt.Errorf("opening filesystem dir: %w", err)
		}
		roots = append(roots, root)
	}
	ret := walk.Roots(ctx, roots...)
	return ret, nil
}

func containers(ctx context.Context, configs model.ContainersConfig) (iter.Seq2[walk.Entry, error], error) {
	var somethingEnabled = false
	for _, cc := range configs {
		if cc.Enabled {
			somethingEnabled = true
			break
		}
	}
	if !somethingEnabled {
		return nil, nil
	}

	ret := walk.Images(ctx, configs)
	return ret, nil
}

func nmaps(ctx context.Context, cfg model.Ports) ([]nmap.Scanner, []netip.Addr, error) {
	if !cfg.Enabled {
		return nil, nil, nil
	}

	if !cfg.IPv4 && !cfg.IPv6 {
		return nil, nil, nil
	}

	var ips []netip.Addr
	if cfg.IPv4 {
		ips = append(ips, netip.MustParseAddr("127.0.0.1"))
	}
	if cfg.IPv6 {
		ips = append(ips, netip.IPv6Loopback())
	}

	var scanners = []nmap.Scanner{
		nmap.NewTLS(),
		nmap.NewSSH(),
	}

	if cfg.Binary != "" {
		for idx, s := range scanners {
			scanners[idx] = s.WithNmapBinary(cfg.Binary)
		}
	}
	if cfg.Ports != "" {
		for idx, s := range scanners {
			scanners[idx] = s.WithPorts(cfg.Ports)
		}
	}

	return scanners, ips, nil

}
