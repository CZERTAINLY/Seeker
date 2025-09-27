package nmap

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	cc "github.com/CZERTAINLY/Seeker/internal/cryptoconst"
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

	{
		f, err := os.Create("raw.json")
		if err != nil {
			panic(err)
		}
		defer f.Close()
		e := json.NewEncoder(f)
		e.SetIndent("", "  ")
		if err := e.Encode(r); err != nil {
			panic(err)
		}
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
		compo := portToComponents(primaryAddr, port)
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

func portToComponents(primaryAddr string, port nmap.Port) []cdx.Component {
	state := strings.ToLower(port.State.State)
	proto := strings.ToLower(port.Protocol)

	ref := fmt.Sprintf("nmap:%s/%s/%s:%d", proto, state, primaryAddr, port.ID)

	// Collect script outputs (e.g. ssl-enum-ciphers, ssl-cert)
	scriptProps, compos := parseScripts(port.Scripts)

	props := []cdx.Property{
		{Name: "nmap:port", Value: fmt.Sprintf("%d", port.ID)},
		{Name: "nmap:protocol", Value: port.Protocol},
		{Name: "nmap:service_name", Value: port.Service.Name},
		{Name: "nmap:service_product", Value: port.Service.Product},
		{Name: "nmap:service_version", Value: port.Service.Version},
	}
	props = append(props, scriptProps...)

	portCompo := cdx.Component{
		BOMRef:     ref,
		Type:       cdx.ComponentTypeData,
		Name:       fmt.Sprintf("%s/%d", port.Protocol, port.ID),
		Version:    "", // no version for port
		PackageURL: "",
		Properties: &props,
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

func parseScripts(scripts []nmap.Script) ([]cdx.Property, []cdx.Component) {
	var scriptProps []cdx.Property
	var components []cdx.Component
	for _, s := range scripts {
		switch s.ID {
		case "ssl-enum-ciphers":
			components = append(components, sslEnumCiphers(s)...)
		default:
			scriptProps = append(scriptProps, cdx.Property{
				Name:  fmt.Sprintf("nmap:script:%s", s.ID),
				Value: s.Output,
			})
		}
	}
	return scriptProps, components
}

func sslEnumCiphers(s nmap.Script) []cdx.Component {
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
					CipherSuites: cipherSuites(row.Tables),
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
		name = strings.ToLower(name)
		name = strings.Replace(name, "v", "@", 1)
		return "crypto/protocol/" + name
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

func identifiers(name string) *[]string {
	code, ok := cc.Code(name)
	if !ok {
		return nil
	}
	var ret = []string{
		fmt.Sprintf("0x%X", byte(code>>8)),
		fmt.Sprintf("0x%X", byte(code&0xFF)),
	}
	return &ret
}

func cipherSuites(tables []nmap.Table) *[]cdx.CipherSuite {
	var ret []cdx.CipherSuite
	for _, row := range tables {
		if row.Key != "ciphers" {
			continue
		}
		for _, cipher := range row.Tables {
			for _, element := range cipher.Elements {
				if element.Key == "name" {
					s := cdx.CipherSuite{
						Name:       element.Value,
						Algorithms: &[]cdx.BOMReference{
							// TODO: where to read algorithms?
						},
						Identifiers: identifiers(element.Value),
					}
					ret = append(ret, s)
				}
			}
		}
	}
	if len(ret) == 0 {
		return nil
	}
	return &ret
}

/*
  "components": [
          "cipherSuites": [
            {
              "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
              "algorithms": [
                "crypto/algorithm/ecdh-curve25519@1.3.132.1.12",
                "crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1",
                "crypto/algorithm/aes-256-gcm@2.16.840.1.101.3.4.1.46",
                "crypto/algorithm/sha-384@2.16.840.1.101.3.4.2.9"
              ],
              "identifiers": [ "0xC0", "0x30" ]
            }
          ],
          "cryptoRefArray": [
            "crypto/certificate/google.com@sha256:1e15e0fbd3ce95bde5945633ae96add551341b11e5bae7bba12e98ad84a5beb4"
          ]
        },
        "oid": "1.3.18.0.2.32.104"
      }
    },
*/
