package nmap

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	props "github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/log"
	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/CZERTAINLY/Seeker/internal/x509"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/Ullaakut/nmap/v3"
)

// Scanner is a wrapper on top of "github.com/Ullaakut/nmap/v3" Scanner
type Scanner struct {
	nmap    string
	ports   []string
	options []nmap.Option
	rawPath string
}

// NewTLS creates a nmap scanner with -sV and --script ssl-enum-ciphers,ssl-cert
// for TLS/SSL (if available) detection
func NewTLS() Scanner {
	return Scanner{
		options: []nmap.Option{
			nmap.WithServiceInfo(),
			nmap.WithScripts("ssl-enum-ciphers", "ssl-cert"),
		},
	}
}

// NewSSH creates a nmap scanner with -sV and --script ssh-hostkey
func NewSSH() Scanner {
	return Scanner{
		options: []nmap.Option{
			nmap.WithServiceInfo(),
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

func (s Scanner) WithRawPath(path string) Scanner {
	s.rawPath = path
	return s
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
	run, err := scan(logCtx, options)
	if err != nil {
		return nil, fmt.Errorf("nmap scan: %w", err)
	}

	if run == nil || len(run.Hosts) == 0 {
		slog.WarnContext(ctx, "nmap scan: no hosts results")
		return nil, nil
	}

	return []model.Detection{
		HostToDetection(ctx, run.Hosts[0]),
	}, nil
}

func scan(ctx context.Context, options []nmap.Option) (*nmap.Run, error) {
	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("creating nmap scanner: %w", err)
	}

	now := time.Now()
	slog.DebugContext(ctx, "scan started")
	scan, warningsp, err := scanner.Run()
	if err != nil {
		slog.DebugContext(ctx, "scan failed", "error", err)
		return nil, fmt.Errorf("nmap scan: %w", err)
	}

	if scan == nil || len(scan.Hosts) == 0 {
		slog.DebugContext(ctx, "scan found nothing")
		return nil, nil
	}

	slog.DebugContext(ctx, "scan finished", "elapsed", time.Since(now).String())

	if warningsp != nil && *warningsp != nil {
		for _, warn := range *warningsp {
			slog.WarnContext(ctx, "scan", "warning", warn)
		}
	}

	return scan, nil
}

func HostToDetection(ctx context.Context, host nmap.Host) model.Detection {
	primaryAddr, hostCompo := hostToComponent(host)
	portCompos := make([]cdx.Component, 0, len(host.Ports))
	portRefs := make([]string, 0, len(host.Ports))
	for _, port := range host.Ports {
		compo := portToComponents(ctx, primaryAddr, port)
		portCompos = append(portCompos, compo...)
		for _, compo := range compo {
			portRefs = append(portRefs, compo.BOMRef)
		}
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

func portToComponents(ctx context.Context, primaryAddr string, port nmap.Port) []cdx.Component {
	state := strings.ToLower(port.State.State)
	proto := strings.ToLower(port.Protocol)

	ref := fmt.Sprintf("nmap:%s/%s/%s:%d", proto, state, primaryAddr, port.ID)

	// Collect script outputs (e.g. ssl-enum-ciphers, ssl-cert)
	scriptProps, compos := parseScripts(ctx, port.Scripts)

	portProps := []cdx.Property{
		{Name: "nmap:port", Value: fmt.Sprintf("%d", port.ID)},
		{Name: "nmap:protocol", Value: port.Protocol},
		{Name: "nmap:service_name", Value: port.Service.Name},
		{Name: "nmap:service_product", Value: port.Service.Product},
		{Name: "nmap:service_version", Value: port.Service.Version},
	}
	portProps = append(portProps, scriptProps...)

	portCompo := cdx.Component{
		BOMRef:     ref,
		Type:       cdx.ComponentTypeData,
		Name:       fmt.Sprintf("%s/%d", port.Protocol, port.ID),
		Version:    "", // no version for port
		PackageURL: "",
		Properties: &portProps,
	}

	return append([]cdx.Component{portCompo}, compos...)
}

func addresses(host nmap.Host) string {
	var addresses []string
	for _, a := range host.Addresses {
		addresses = append(addresses, a.Addr)
	}
	return strings.Join(addresses, ",")
}

func parseScripts(ctx context.Context, scripts []nmap.Script) ([]cdx.Property, []cdx.Component) {
	var scriptProps []cdx.Property
	var components []cdx.Component
	for _, s := range scripts {
		switch s.ID {
		case "ssl-enum-ciphers":
			components = append(components, sslEnumCiphers(ctx, s)...)
		case "ssl-cert":
			components = append(components, sslCert(ctx, s)...)
		case "ssh-hostkey":
			components = append(components, sshHostKey(ctx, s)...)
		default:
			scriptProps = append(scriptProps, cdx.Property{
				Name:  fmt.Sprintf("nmap:script:%s", s.ID),
				Value: s.Output,
			})
		}
	}
	return scriptProps, components
}

func sslEnumCiphers(ctx context.Context, s nmap.Script) []cdx.Component {
	var components []cdx.Component

	for _, row := range s.Tables {
		compo := cdx.Component{
			Name:   row.Key,
			BOMRef: nameToBomRef(row.Key),
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeProtocol,
				ProtocolProperties: &cdx.CryptoProtocolProperties{
					Type:         cdx.CryptoProtocolTypeTLS,
					Version:      nameToProtoVersion(row.Key),
					CipherSuites: cipherSuites(ctx, row.Tables),
				},
				OID: "1.3.18.0.2.32.104",
			},
		}
		components = append(components, compo)
	}

	return components
}

func nameToBomRef(name string) string {
	switch name {
	case "SSLv3.0":
		return "crypto/protocol/ssl@3.0"
	case "TLSv1.0":
		return "crypto/protocol/tls@1.0"
	case "TLSv1.1":
		return "crypto/protocol/tls@1.1"
	case "TLSv1.2":
		return "crypto/protocol/tls@1.2"
	case "TLSv1.3":
		return "crypto/protocol/tls@1.3"
	default:
		return "invalid/" + name
	}
}

func nameToProtoVersion(name string) string {
	bomRef := nameToBomRef(name)
	_, after, ok := strings.Cut(bomRef, "@")
	if !ok {
		return "N/A"
	}
	return after
}

func identifiers(ctx context.Context, name string) (cdx.CipherSuite, bool) {
	spec, ok := props.ParseCipherSuite(name)
	if !ok {
		slog.WarnContext(ctx, "skipping unsupported cipher suite", "name", name)
		return cdx.CipherSuite{}, false
	}

	algorithms := spec.Algorithms()

	code := spec.Code
	var identifiers = []string{
		fmt.Sprintf("0x%X", byte(code>>8)),
		fmt.Sprintf("0x%X", byte(code&0xFF)),
	}
	return cdx.CipherSuite{
		Name:        spec.Name,
		Algorithms:  &algorithms,
		Identifiers: &identifiers,
	}, true
}

func cipherSuites(ctx context.Context, tables []nmap.Table) *[]cdx.CipherSuite {
	var ret []cdx.CipherSuite
	for _, row := range tables {
		if row.Key != "ciphers" {
			continue
		}
		for _, cipher := range row.Tables {
			for _, element := range cipher.Elements {
				if element.Key == "name" {
					suite, ok := identifiers(ctx, element.Value)
					if !ok {
						continue
					}
					ret = append(ret, suite)
				}
			}
		}
	}
	if len(ret) == 0 {
		return nil
	}
	return &ret
}

func sslCert(ctx context.Context, s nmap.Script) []cdx.Component {
	var components []cdx.Component

	for _, row := range s.Elements {
		if row.Key == "pem" {
			val := html.UnescapeString(row.Value)
			detections, err := x509.Detector{}.Detect(ctx, []byte(val), "nmap")
			if err != nil {
				slog.ErrorContext(ctx, "parsing certificate from nmap ssl-cert", "error", err)
				return nil
			}
			for _, d := range detections {
				components = append(components, d.Components...)
			}
			return components
		}
	}
	return nil
}

func sshHostKey(ctx context.Context, s nmap.Script) []cdx.Component {
	var components []cdx.Component

	for _, table := range s.Tables {
		var key, typ, bits, fingerprint string
		for _, row := range table.Elements {
			switch row.Key {
			case "key":
				key = row.Value
			case "type":
				typ = row.Value
			case "bits":
				bits = row.Value
			case "fingerprint":
				fingerprint = row.Value
			}
		}
		algoProp, ok := ParseSSHAlgorithm(typ)
		if !ok {
			slog.WarnContext(ctx, "unsupported ssh algorithm", "algorithm", typ)
			continue
		}
		compo := cdx.Component{
			BOMRef: "crypto/ssh-hostkey/" + typ + "@" + bits,
			Name:   typ,
			Type:   cdx.ComponentTypeCryptographicAsset,
			CryptoProperties: &cdx.CryptoProperties{
				AssetType:           cdx.CryptoAssetTypeAlgorithm,
				AlgorithmProperties: &algoProp,
				OID:                 algoProp.ParameterSetIdentifier,
			},
		}
		props.SetComponentProp(&compo, props.CzertainlyComponentSSHHostKeyContent, key)
		props.SetComponentProp(&compo, props.CzertainlyComponentSSHHostKeyFingerprintContent, fingerprint)
		components = append(components, compo)
	}

	return components
}
