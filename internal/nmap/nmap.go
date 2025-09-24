package nmap

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/log"
	"github.com/CZERTAINLY/Seeker/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/Ullaakut/nmap/v3"
)

// Scanner is a wrapper on top of "github.com/Ullaakut/nmap/v3" Scanner
type Scanner struct {
	nmap    string
	ports   []string
	options []nmap.Option
}

// NewTLS creates a nmap scanner with -sV and --script ssl-enum-ciphers,ssl-cert
// for TLS/SSL (if available) detection
func NewTLS() Scanner {
	return Scanner{
		options: []nmap.Option{
			// -sV
			nmap.WithServiceInfo(),
			// --script ssl-enum-ciphers,ssl-cert
			nmap.WithScripts("ssl-enum-ciphers", "ssl-cert"),
		},
	}
}

// NewSSH creates a nmap scanner with -sV and --script ssh-hostkey
func NewSSH() Scanner {
	return Scanner{
		options: []nmap.Option{
			// -sV
			nmap.WithServiceInfo(),
			// --script ssl-enum-ciphers,ssl-cert
			nmap.WithScripts("ssh-hostkey"),
		},
	}
}

func (s Scanner) WithNmapBinary(nmap string) Scanner {
	s.nmap = nmap
	return s
}

func (s Scanner) WithPorts(defs ...string) Scanner {
	ret := s
	ret.ports = append(append([]string(nil), ret.ports...), defs...)
	return ret
}

func (s Scanner) Detect(ctx context.Context, addr netip.Addr) ([]model.Detection, error) {
	options := s.options
	if s.nmap != "" {
		options = append(options, nmap.WithBinaryPath(s.nmap))
	}

	ports := s.ports
	if ports == nil {
		ports = []string{"1-65535"}
	}
	options = append(options, nmap.WithPorts(ports...))

	options = append(options, []nmap.Option{
		nmap.WithTargets(addr.String()),
	}...)

	if addr.Is6() {
		options = append(options, nmap.WithIPv6Scanning())
	}

	logCtx := log.ContextAttrs(
		ctx,
		slog.String("scanner", "nmap"),
		slog.GroupAttrs(
			"options",
			slog.String("nmap", s.nmap),
			slog.Any("ports", ports),
		),
		slog.String("target", addr.String()),
	)
	r, err := scan(logCtx, options)
	if err != nil {
		return nil, fmt.Errorf("nmap scan: %w", err)
	}
	return []model.Detection{
		hostToDetection(r.Info),
	}, nil
}

type result struct {
	Info nmap.Host
}

func scan(ctx context.Context, options []nmap.Option) (result, error) {
	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return result{}, fmt.Errorf("creating nmap scanner: %w", err)
	}

	now := time.Now()
	slog.DebugContext(ctx, "scan started")
	scan, warningsp, err := scanner.Run()
	if err != nil {
		slog.DebugContext(ctx, "scan failed", "error", err)
		return result{}, fmt.Errorf("nmap scan: %w", err)
	}

	if len(scan.Hosts) == 0 {
		slog.DebugContext(ctx, "scan found nothing")
		return result{}, model.ErrNoMatch
	}

	slog.DebugContext(ctx, "scan finished", "elapsed", time.Since(now).String())

	if *warningsp != nil {
		for _, warn := range *warningsp {
			slog.WarnContext(ctx, "scan", "warning", warn)
		}
	}

	return result{
		Info: scan.Hosts[0],
	}, nil
}

func hostToDetection(host nmap.Host) model.Detection {
	primaryAddr, hostCompo := hostToComponent(host)
	portCompos := make([]cdx.Component, 0, len(host.Ports))
	portRefs := make([]string, 0, len(host.Ports))
	for _, port := range host.Ports {
		compo := portToComponent(primaryAddr, port)
		portCompos = append(portCompos, compo)
		portRefs = append(portRefs, compo.BOMRef)
	}

	var dependencies []cdx.Dependency
	if len(portCompos) > 0 {
		dependencies = append(dependencies, cdx.Dependency{
			Ref:          hostCompo.BOMRef,
			Dependencies: &portRefs,
		})
		for _, ref := range portRefs {
			dependencies = append(dependencies, cdx.Dependency{Ref: ref})
		}
	}
	return model.Detection{
		Path:         "nmap://" + primaryAddr,
		Components:   append([]cdx.Component{hostCompo}, portCompos...),
		Dependencies: dependencies,
	}
}

func hostToComponent(host nmap.Host) (string, cdx.Component) {
	var primaryAddr string
	if len(host.Addresses) > 0 {
		primaryAddr = host.Addresses[0].Addr
	} else {
		primaryAddr = "unknown"
	}

	return primaryAddr, cdx.Component{
		BOMRef: fmt.Sprintf("nmap:host/%s", primaryAddr),
		Type:   cdx.ComponentTypeApplication, // host itself as "application" (opinionated)
		Name:   fmt.Sprintf("host:%s", primaryAddr),
		Properties: &[]cdx.Property{
			{Name: "nmap:addresses", Value: addresses(host)},
			{Name: "nmap:status", Value: host.Status.State},
		},
	}
}

func portToComponent(primaryAddr string, port nmap.Port) cdx.Component {
	state := strings.ToLower(port.State.State)
	proto := strings.ToLower(port.Protocol)

	ref := fmt.Sprintf("nmap:%s/%s/%s:%d", proto, state, primaryAddr, port.ID)

	// Collect script outputs (e.g. ssl-enum-ciphers, ssl-cert)
	var scriptProps []cdx.Property
	for _, s := range port.Scripts {
		out := s.Output
		scriptProps = append(scriptProps, cdx.Property{
			Name:  fmt.Sprintf("nmap:script:%s", s.ID),
			Value: out,
		})
	}

	props := []cdx.Property{
		{Name: "nmap:port", Value: fmt.Sprintf("%d", port.ID)},
		{Name: "nmap:protocol", Value: port.Protocol},
		{Name: "nmap:service_name", Value: port.Service.Name},
		{Name: "nmap:service_product", Value: port.Service.Product},
		{Name: "nmap:service_version", Value: port.Service.Version},
	}
	props = append(props, scriptProps...)

	return cdx.Component{
		BOMRef:     ref,
		Type:       cdx.ComponentTypeDevice,
		Name:       fmt.Sprintf("%s/%d", port.Protocol, port.ID),
		Version:    "", // no version for port
		PackageURL: "",
		Properties: &props,
	}
}

func addresses(host nmap.Host) string {
	var addresses []string
	for _, a := range host.Addresses {
		addresses = append(addresses, a.Addr)
	}
	return strings.Join(addresses, ",")
}
