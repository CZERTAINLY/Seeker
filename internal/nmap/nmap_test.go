package nmap

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	nmapv3 "github.com/Ullaakut/nmap/v3"
	"github.com/stretchr/testify/require"
)

func TestScanner(t *testing.T) {
	if testing.Short() {
		t.Skipf("%s is skipped via -short", t.Name())
	}
	t.Parallel()
	nmapPath, err := exec.LookPath("nmap")
	require.NoError(t, err, "nmap binary is missing in PATH, please install it first")

	scanner := NewTLS().
		WithNmapBinary(nmapPath)
	sshScanner := NewSSH().
		WithNmapBinary(nmapPath)

	type given struct {
		addrPort netip.AddrPort
		scanner  Scanner
	}

	var testCases = []struct {
		scenario string
		given    given
	}{
		{
			scenario: "tls: ipv4",
			given: given{
				addrPort: http4,
				scanner:  scanner,
			},
		},
		{
			scenario: "tls: ipv6",
			given: given{
				addrPort: http6,
				scanner:  scanner,
			},
		},
		{
			scenario: "ssh: ipv4",
			given: given{
				addrPort: ssh4,
				scanner:  sshScanner,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			t.Parallel()
			port := tc.given.addrPort.Port()
			addr := tc.given.addrPort.Addr()

			tcScanner := tc.given.scanner.WithPorts(strconv.Itoa(int(port)))
			detections, err := tcScanner.Detect(t.Context(), addr)
			require.NoError(t, err)
			require.NotEmpty(t, detections)

			for _, d := range detections {
				t.Logf("%+v", d)
			}
		})
	}
}

func TestParseTLS(t *testing.T) {
	if testing.Short() {
		t.Skipf("%s is skipped via -short", t.Name())
	}
	t.Parallel()
	rawJSON, err := testdata.ReadFile("testdata/raw.json")
	require.NoError(t, err)
	require.NotEmpty(t, rawJSON)

	var raw struct {
		Info nmapv3.Host `json:"Info"`
	}
	err = json.NewDecoder(bytes.NewReader(rawJSON)).Decode(&raw)
	require.NoError(t, err)

	detections := HostToDetection(t.Context(), raw.Info)

	for i, compo := range detections.Components {
		t.Logf("[%d]name: %+v", i, compo.Name)
		if compo.CryptoProperties == nil || strings.HasPrefix(compo.Name, "CN=www.ssllabs.com") {
			continue
		}
		if compo.Name == "ecdsa-sha2-nistp256" {
			require.NotNil(t, compo.CryptoProperties)
			require.NotNil(t, compo.CryptoProperties.AlgorithmProperties)
			require.NotNil(t, compo.Properties)
			continue
		}
		require.NotNil(t, compo.CryptoProperties)
		require.NotNil(t, compo.CryptoProperties.ProtocolProperties)
		require.NotNil(t, compo.CryptoProperties.ProtocolProperties.CipherSuites)
		for j, suite := range *compo.CryptoProperties.ProtocolProperties.CipherSuites {
			t.Logf("[%d.%d]%+v", i, j, suite.Name)
			require.NotNil(t, suite.Algorithms)
			require.NotNil(t, suite.Identifiers)
			for k, algo := range *suite.Algorithms {
				t.Logf("[%d.%d.%d] algo: %s", i, j, k, algo)
			}
			t.Logf("[%d.%d]identifiers: %+v", i, j, *suite.Identifiers)
		}
	}
}

// Merged internal helper tests

func TestNameToBomRefAndProtoVersion(t *testing.T) {
	t.Parallel()
	// known mapping
	require.Equal(t, "crypto/protocol/tls@1.3", nameToBomRef("TLSv1.3"))
	require.Equal(t, "1.3", nameToProtoVersion("TLSv1.3"))
	// unknown mapping hits default branch
	require.Equal(t, "invalid/TLSv1.4", nameToBomRef("TLSv1.4"))
	require.Equal(t, "N/A", nameToProtoVersion("TLSv1.4"))
}

func TestIdentifiers_Unsupported(t *testing.T) {
	t.Parallel()
	suite, ok := identifiers(t.Context(), "TLS_FAKE_WITH_NONE_NONE")
	require.False(t, ok)
	require.Empty(t, suite)
}

func TestParseScripts_DefaultAndNoPem(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	scripts := []nmapv3.Script{
		{ID: "some-unknown-script", Output: "hello"},
		{ID: "ssl-cert", Elements: []nmapv3.Element{{Key: "not-pem", Value: "ignored"}}},
	}
	props, comps := parseScripts(ctx, scripts)
	require.Len(t, props, 1)
	require.Equal(t, cdx.Property{Name: "nmap:script:some-unknown-script", Value: "hello"}, props[0])
	require.Nil(t, comps) // ssl-cert without pem yields no components
}

func TestSSHHostKey_UnsupportedAlgo(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	scripts := nmapv3.Script{
		ID: "ssh-hostkey",
		Tables: []nmapv3.Table{
			{Elements: []nmapv3.Element{{Key: "type", Value: "unsupported-algo"}}},
		},
	}
	comps := sshHostKey(ctx, scripts)
	require.Empty(t, comps)
}

func TestSSHHostKey_SupportedAlgo(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	s := nmapv3.Script{
		ID: "ssh-hostkey",
		Tables: []nmapv3.Table{ // one hostkey entry
			{Elements: []nmapv3.Element{
				{Key: "type", Value: "ecdsa-sha2-nistp256"},
				{Key: "bits", Value: "256"},
				{Key: "key", Value: "AAAAB3NzaC1yc2EAAAADAQABAAABAQ=="},
				{Key: "fingerprint", Value: "aa:bb:cc"},
			}},
		},
	}
	comps := sshHostKey(ctx, s)
	require.Len(t, comps, 1)
	require.Equal(t, "crypto/ssh-hostkey/ecdsa-sha2-nistp256@256", comps[0].BOMRef)
	require.NotNil(t, comps[0].CryptoProperties)
	require.NotNil(t, comps[0].CryptoProperties.AlgorithmProperties)
	// properties set by SetComponentProp
	require.NotNil(t, comps[0].Properties)
	foundKey, foundFP := false, false
	for _, p := range *comps[0].Properties {
		if p.Name == "czertainly:component:ssh_hostkey:content" && p.Value != "" {
			foundKey = true
		}
		if p.Name == "czertainly:component:ssh_hostkey:fingerprint_content" && p.Value == "aa:bb:cc" {
			foundFP = true
		}
	}
	require.True(t, foundKey)
	require.True(t, foundFP)
}

func TestSSLCert_SuccessAndErrorPaths(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	// success path: generate a self-signed cert and encode as PEM
	cert, err := generateSelfSignedCert()
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	require.NotEmpty(t, pemBytes)
	s := nmapv3.Script{ID: "ssl-cert", Elements: []nmapv3.Element{{Key: "pem", Value: string(pemBytes)}}}
	comps := sslCert(ctx, s)
	// at least one component (the certificate) should be detected
	require.NotNil(t, comps)
	require.NotEmpty(t, comps)

	// error path: invalid PEM base64 -> x509 parser error -> function returns nil
	badPEM := "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n"
	sBad := nmapv3.Script{ID: "ssl-cert", Elements: []nmapv3.Element{{Key: "pem", Value: badPEM}}}
	compsBad := sslCert(ctx, sBad)
	require.Nil(t, compsBad)

	// no detections but no error: a valid PEM header with empty body is unlikely; simulate by passing non-pem key path
	nonPem := nmapv3.Script{ID: "ssl-cert", Elements: []nmapv3.Element{{Key: "not-pem", Value: "ignored"}}}
	compsNone := sslCert(ctx, nonPem)
	require.Nil(t, compsNone)
}

func TestHostToComponent_NoAddresses(t *testing.T) {
	t.Parallel()
	addr, comp := hostToComponent(nmapv3.Host{Addresses: nil})
	require.Equal(t, "unknown", addr)
	require.Equal(t, "host:unknown", comp.Name)
}

func TestPortToComponents_Properties(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	p := nmapv3.Port{
		ID:       443,
		State:    nmapv3.State{State: "open"},
		Protocol: "tcp",
		Service:  nmapv3.Service{Name: "https", Product: "nginx", Version: "1.23"},
	}
	comps := portToComponents(ctx, "127.0.0.1", p)
	require.NotEmpty(t, comps)
	pc := comps[0]
	require.Equal(t, "tcp/443", pc.Name)
	require.NotNil(t, pc.Properties)
	propsMap := map[string]string{}
	for _, pr := range *pc.Properties {
		propsMap[pr.Name] = pr.Value
	}
	require.Equal(t, "443", propsMap["nmap:port"])
	require.Equal(t, "tcp", propsMap["nmap:protocol"])
	require.Equal(t, "https", propsMap["nmap:service_name"])
	require.Equal(t, "nginx", propsMap["nmap:service_product"])
	require.Equal(t, "1.23", propsMap["nmap:service_version"])
}

func TestAddresses_Helper(t *testing.T) {
	t.Parallel()
	h := nmapv3.Host{Addresses: []nmapv3.Address{{Addr: "1.2.3.4"}, {Addr: "::1"}}}
	require.Equal(t, "1.2.3.4,::1", addresses(h))
}
