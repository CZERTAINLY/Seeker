package nmap_test

import (
	"net/netip"
	"os/exec"
	"strconv"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/nmap"
	"github.com/stretchr/testify/require"
)

func TestScanner(t *testing.T) {
	t.Parallel()

	nmapPath, err := exec.LookPath("nmap")
	require.NoError(t, err, "nmap binary is missing in PATH, please install it first")

	tlsScanner := nmap.NewTLS().WithNmapBinary(nmapPath)
	sshScanner := nmap.NewSSH().WithNmapBinary(nmapPath)

	type given struct {
		addrPort netip.AddrPort
		scanner  nmap.Scanner
	}

	var testCases = []struct {
		scenario string
		given    given
	}{
		{
			scenario: "tls: ipv4",
			given: given{
				addrPort: http4,
				scanner:  tlsScanner,
			},
		},
		{
			scenario: "tls: ipv6",
			given: given{
				addrPort: http6,
				scanner:  tlsScanner,
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

			tlsScanner = tlsScanner.WithPorts(strconv.Itoa(int(port)))
			detections, err := tlsScanner.Detect(t.Context(), addr)
			require.NoError(t, err)
			require.NotEmpty(t, detections)

			for _, d := range detections {
				t.Logf("%+v", d)
			}
		})
	}

}
