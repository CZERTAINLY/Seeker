package cdxprops

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops/czertainly"
	"github.com/CZERTAINLY/Seeker/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

const (
	rsaIdentifier = "rsa@1.2.840.113549.1.1.1"
)

var (
	cryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionVerify}
	algoMap         = map[string]cdx.CryptoAlgorithmProperties{
		"ecdsa-sha2-nistp256": {
			ParameterSetIdentifier: "nistp256@1.2.840.10045.3.1.7",
			Curve:                  "nistp256",
		},
		"ecdsa-sha2-nistp384": {
			ParameterSetIdentifier: "nistp384@1.3.132.0.34",
			Curve:                  "nistp384",
		},
		"ecdsa-sha2-nistp521": {
			ParameterSetIdentifier: "nistp521@1.3.132.0.35",
			Curve:                  "nistp521",
		},
		"ssh-ed25519": {
			ParameterSetIdentifier: "ed25519@1.3.101.112",
			Curve:                  "ed25519",
		},
		"rsa-sha2-256": {
			ParameterSetIdentifier: rsaIdentifier,
		},
		"rsa-sha2-512": {
			ParameterSetIdentifier: rsaIdentifier,
		},
		"ssh-rsa": { // legacy
			ParameterSetIdentifier: rsaIdentifier,
		},
	}
)

func (c Converter) parseNmap(ctx context.Context, nmap model.Nmap) (compos []cdx.Component, deps []cdx.Dependency, services []cdx.Service, err error) {
	for _, port := range nmap.Ports {
		switch port.Service.Name {
		case "ssh":
			compos = append(compos, c.sshToCompos(ctx, port)...)
		case "ssl", "http", "https":
			c, d := c.tlsToCompos(ctx, port)
			compos = append(compos, c...)
			deps = append(deps, d...)
		default:
			err = fmt.Errorf("can't parse unsupported nmap service: %s", port.Service.Name)
			return
		}
	}
	// FIXME: handle cdx services too
	return
}

func (c Converter) sshToCompos(_ context.Context, port model.NmapPort) []cdx.Component {
	ret := make([]cdx.Component, 0, len(port.SSHHostKeys))
	for _, hkey := range port.SSHHostKeys {
		compo := c.ParseSSHHostKey(hkey)
		ret = append(ret, compo)
	}
	return ret
}

func (c Converter) tlsToCompos(ctx context.Context, port model.NmapPort) ([]cdx.Component, []cdx.Dependency) {
	compos := make([]cdx.Component, 0, len(port.Ciphers)+len(port.TLSCerts))
	var dependencies []cdx.Dependency

	for _, cipher := range port.Ciphers {
		proto, ver := ParseTLSVersion(cipher.Name)
		compo := cdx.Component{
			Name:   cipher.Name,
			Type:   cdx.ComponentTypeCryptographicAsset,
			BOMRef: "crypto/protocol/" + proto + "@" + ver,
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeProtocol,
				ProtocolProperties: &cdx.CryptoProtocolProperties{
					Type:         "tls",
					Version:      ver,
					CipherSuites: ParseTLSCiphers(ctx, cipher.Ciphers),
				},
			},
		}
		compos = append(compos, compo)
	}

	for _, certHit := range port.TLSCerts {
		detection := c.CertHit(ctx, certHit)
		if detection == nil {
			slog.WarnContext(ctx, "can't convert nmap TLS certificate to components: ignoring", "location", certHit.Location, "source", certHit.Source)
			continue
		}
		compos = append(compos, detection.Components...)
		dependencies = append(dependencies, detection.Dependencies...)
	}
	return compos, dependencies
}

func ParseTLSVersion(input string) (string, string) {
	// Common TLS/SSL version patterns
	patterns := map[string]struct {
		protocol string
		version  string
	}{
		"TLSv1.3": {"tls", "1.3"},
		"TLSv1.2": {"tls", "1.2"},
		"TLSv1.1": {"tls", "1.1"},
		"TLSv1.0": {"tls", "1.0"},
		"TLSv1":   {"tls", "1.0"},
		"SSLv3":   {"ssl", "3.0"},
		"SSLv2":   {"ssl", "2.0"},
		// Alternative formats
		"TLS1.3":  {"tls", "1.3"},
		"TLS1.2":  {"tls", "1.2"},
		"TLS1.1":  {"tls", "1.1"},
		"TLS1.0":  {"tls", "1.0"},
		"TLS 1.3": {"tls", "1.3"},
		"TLS 1.2": {"tls", "1.2"},
		"TLS 1.1": {"tls", "1.1"},
		"TLS 1.0": {"tls", "1.0"},
	}

	if result, ok := patterns[input]; ok {
		return result.protocol, result.version
	}

	return "n/a", "n/a"
}

func ParseTLSCiphers(ctx context.Context, ciphers []string) *[]cdx.CipherSuite {
	ret := make([]cdx.CipherSuite, 0, len(ciphers))
	for _, c := range ciphers {
		suite, ok := ParseCipherSuite(c)
		if !ok {
			slog.WarnContext(ctx, "cipher suite not supported: ignoring", "name", c)
			continue
		}
		algos := suite.Algorithms()
		var identifiers = []string{
			fmt.Sprintf("0x%X", byte(suite.Code>>8)),
			fmt.Sprintf("0x%X", byte(suite.Code&0xFF)),
		}

		s := cdx.CipherSuite{
			Name:        c,
			Algorithms:  &algos,
			Identifiers: &identifiers,
		}
		ret = append(ret, s)
	}
	return &ret
}

// ParseSSHAlgorithm returns CycloneDX crypto algorithm properties for a known SSH
// host key algorithm string. It reports ok=false if the algorithm is unsupported.
func parseSSHAlgorithm(algo string) cdx.CryptoAlgorithmProperties {
	p, ok := algoMap[algo]

	if !ok {
		p.ParameterSetIdentifier = "unknown"
		p.Curve = ""
	}

	p.Primitive = cdx.CryptoPrimitiveSignature
	p.CryptoFunctions = cryptoFunctions
	return p
}

func (c Converter) ParseSSHHostKey(key model.SSHHostKey) cdx.Component {
	algoProp := parseSSHAlgorithm(key.Type)
	compo := cdx.Component{
		BOMRef: "crypto/algorithm/" + key.Type + "@" + key.Bits,
		Name:   key.Type,
		Type:   cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &algoProp,
			OID:                 algoProp.ParameterSetIdentifier,
		},
	}

	if c.czertainly {
		props := czertainly.SSHHostKeyProperties(nil, key)
		compo.Properties = &props
	}

	return compo
}
