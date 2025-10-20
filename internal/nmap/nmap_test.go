package nmap

import (
	"bytes"
	"encoding/json"
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
	require.Equal(t, "crypto/protocol/tls@1.4", nameToBomRef("TLSv1.4"))
	require.Equal(t, "1.4", nameToProtoVersion("TLSv1.4"))
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

func TestCipherSuites_Filtering(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	// no "ciphers" key
	require.Nil(t, cipherSuites(ctx, []nmapv3.Table{{Key: "foo"}}))
	// unknown cipher names should be skipped
	tables := []nmapv3.Table{
		{Key: "ciphers", Tables: []nmapv3.Table{{Elements: []nmapv3.Element{{Key: "name", Value: "TLS_FAKE_WITH_NONE_NONE"}}}}},
	}
	require.Nil(t, cipherSuites(ctx, tables))
	// include a known suite to ensure it is parsed
	tables = []nmapv3.Table{
		{Key: "ciphers", Tables: []nmapv3.Table{{Elements: []nmapv3.Element{{Key: "name", Value: "TLS_AES_128_GCM_SHA256"}}}}},
	}
	suites := cipherSuites(ctx, tables)
	require.NotNil(t, suites)
	require.Len(t, *suites, 1)
	// verify identifiers populated
	require.NotEmpty(t, (*suites)[0].Identifiers)
	require.NotEmpty(t, (*suites)[0].Algorithms)
}
