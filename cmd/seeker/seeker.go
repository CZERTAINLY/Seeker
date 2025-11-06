package main

import (
	"context"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/netip"
	"os"

	"github.com/CZERTAINLY/Seeker/internal/bom"
	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/gitleaks"
	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/CZERTAINLY/Seeker/internal/nmap"
	"github.com/CZERTAINLY/Seeker/internal/scan"
	"github.com/CZERTAINLY/Seeker/internal/walk"
	"github.com/CZERTAINLY/Seeker/internal/x509"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/sync/errgroup"
)

// Seeker is a component, which encapsulates the scan functionality and executes it.
type Seeker struct {
	detectors   []scan.Detector
	filesystems iter.Seq2[walk.Entry, error]
	containers  iter.Seq2[walk.Entry, error]
	nmaps       []nmap.Scanner
	ips         []netip.Addr
}

func NewSeeker(ctx context.Context, x509Scanner x509.Scanner, leaksScanner *gitleaks.Scanner, config model.Scan) (Seeker, error) {
	if config.Version != 0 {
		return Seeker{}, fmt.Errorf("config version %d is not supported, expected 0", config.Version)
	}

	filesystems, err := filesystems(ctx, config.Filesystem)
	if err != nil {
		slog.WarnContext(ctx, "initializing filesytem scan failed", "error", err)
		filesystems = nil
	}

	containers := containers(ctx, config.Containers)
	nmaps, ips := nmaps(ctx, config.Ports)

	detectors := make([]scan.Detector, 0, 2)
	detectors = append(detectors, x509Detector{s: x509Scanner})
	if leaksScanner != nil {
		detectors = append(detectors, leaksDetector{s: leaksScanner})
	}

	return Seeker{
		detectors:   detectors,
		filesystems: filesystems,
		containers:  containers,
		nmaps:       nmaps,
		ips:         ips,
	}, nil
}

func (s Seeker) Do(ctx context.Context, out io.Writer) error {
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
		scanner := scan.New(4, s.detectors)
		g.Go(func() error {
			goScan(ctx, scanner, s.filesystems, detections)
			return nil
		})
	}

	// containers scanners
	if s.containers != nil {
		scanner := scan.New(2, s.detectors)
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
	nmapScan, err := scanner.Scan(ctx, ip)
	if err != nil {
		slog.ErrorContext(ctx, "nmap scan failed", "error", err)
	}
	compos := cdxprops.ParseNmap(ctx, nmapScan)
	detections <- model.Detection{Path: "nmap", Components: compos}
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
			slog.WarnContext(ctx, "can't open dir, skipping", "dir", path, "error", err)
			continue
		}
		roots = append(roots, root)
	}
	ret := walk.Roots(ctx, roots...)
	return ret, nil
}

func containers(ctx context.Context, config model.Containers) iter.Seq2[walk.Entry, error] {
	if !config.Enabled {
		return nil
	}

	ret := walk.Images(ctx, config.Config)
	return ret
}

func nmaps(_ context.Context, cfg model.Ports) ([]nmap.Scanner, []netip.Addr) {
	if !cfg.Enabled {
		return nil, nil
	}

	if !cfg.IPv4 && !cfg.IPv6 {
		return nil, nil
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

	return scanners, ips
}

type leaksDetector struct {
	s *gitleaks.Scanner
}

func (d leaksDetector) Detect(ctx context.Context, b []byte, path string) ([]model.Detection, error) {
	leaks, err := d.s.Scan(ctx, b, path)
	if err != nil {
		return nil, err
	}
	compos := make([]cdx.Component, 0, len(leaks))
	for _, leak := range leaks {
		if leak.RuleID == "" {
			continue
		}
		compo := cdxprops.LeakToComponent(leak)
		compos = append(compos, compo)
	}
	return []model.Detection{
		{Components: compos},
	}, nil
}

func (d leaksDetector) LogAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("detector", "gitleaks"),
	}
}

type x509Detector struct {
	s x509.Scanner
}

func (d x509Detector) Detect(ctx context.Context, b []byte, path string) ([]model.Detection, error) {
	hits, err := d.s.Scan(ctx, b, path)
	if err != nil {
		return nil, err
	}

	compos := make([]cdx.Component, 0, len(hits))
	for _, hit := range hits {
		compo, err := cdxprops.CertHitToComponent(ctx, hit)
		if err != nil {
			slog.WarnContext(ctx, "can't convert certificate to cdx.Component", "error", err, "path", hit.Location, "source", hit.Source)
			continue
		}
		compos = append(compos, compo)
	}
	return []model.Detection{
		{Components: compos},
	}, nil
}

func (s x509Detector) LogAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("detector", "x509"),
	}
}
