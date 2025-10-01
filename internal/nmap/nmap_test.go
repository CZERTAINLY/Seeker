package nmap_test

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	cznmap "github.com/CZERTAINLY/Seeker/internal/nmap"
	"github.com/stretchr/testify/require"

	"github.com/Ullaakut/nmap/v3"
)

func TestScanner(t *testing.T) {
	t.Parallel()

	nmapPath, err := exec.LookPath("nmap")
	require.NoError(t, err, "nmap binary is missing in PATH, please install it first")

	scanner := cznmap.NewTLS().WithNmapBinary(nmapPath)
	sshScanner := cznmap.NewSSH().WithNmapBinary(nmapPath)

	type given struct {
		addrPort netip.AddrPort
		scanner  cznmap.Scanner
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
		Info nmap.Host `json:"Info"`
	}
	err = json.NewDecoder(bytes.NewReader(rawJSON)).Decode(&raw)
	require.NoError(t, err)

	detections := cznmap.HostToDetection(raw.Info)

	for i, compo := range detections.Components {
		t.Logf("[%d]name: %+v", i, compo.Name)
		if compo.CryptoProperties == nil || strings.HasPrefix(compo.Name, "CN=www.ssllabs.com") {
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
