package netscan_test

import (
	"iter"
	"net/netip"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/netscan"

	"github.com/stretchr/testify/require"
)

func TestLocalPortsDial(t *testing.T) {
	t.Parallel()

	var testCases = []struct {
		scenario string
		given    iter.Seq[netip.AddrPort]
	}{
		{
			scenario: "LocalPortsDial",
			given:    netscan.LocalPortsDial(t.Context()),
		},
		{
			scenario: "LocalPorts",
			given:    netscan.LocalPorts(t.Context()),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			seq := tc.given
			requirePorts(t, seq)
		})
	}
}

func TestLocalPortsNetlink(t *testing.T) {
	t.Parallel()
	seq, err := netscan.LocalPortsNetlink()
	if err != nil {
		t.Skipf("LocalPortsNetlink not available: %s", err)
	}
	requirePorts(t, seq)
}

func requirePorts(t *testing.T, seq iter.Seq[netip.AddrPort]) {
	t.Helper()
	var ipv4Port bool
	var ipv6Port bool
	for ap := range seq {
		if ap.Port() == ipv4.Port() {
			ipv4Port = true
		}
		if ap.Port() == ipv6.Port() {
			ipv6Port = true
		}
	}
	require.Truef(t, ipv4Port, "ipv4 port :%d was not seen", ipv4.Port())
	require.Truef(t, ipv6Port, "ipv6 port :%d was not seen", ipv6.Port())
}
