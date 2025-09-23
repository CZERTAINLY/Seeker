package netscan

import (
	"context"
	"errors"
	"iter"
	"net"
	"net/netip"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/parallel"
)

var (
	errNotListening = errors.New("not listening")
)

// LocalPortsDial scans local TCP ports by attempting to open connections tcp to them.
// It can access the list of ip addresses, if not provided it fallback to 127.0.0.1 and [::]
func LocalPortsDial(ctx context.Context, addresses ...netip.Addr) iter.Seq[netip.AddrPort] {
	if addresses == nil {
		addresses = []netip.Addr{
			netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			netip.IPv6Unspecified(),
		}
	}

	return func(yield func(netip.AddrPort) bool) {
		seq := parallel.NewMap(ctx, 4, opened).Iter(addPort2Seq2(addresses...))
		for addr, err := range seq {
			if err != nil {
				continue
			}
			if !yield(addr) {
				break
			}
		}
	}
}

func opened(ctx context.Context, adr netip.AddrPort) (netip.AddrPort, error) {
	var zero netip.AddrPort
	conn, err := net.DialTimeout("tcp", adr.String(), 500*time.Millisecond)
	if err != nil {
		return zero, errNotListening
	}
	err = conn.Close()
	if err != nil {
		return zero, err
	}
	return adr, nil
}

func addPort2Seq2(addresses ...netip.Addr) iter.Seq2[netip.AddrPort, error] {
	return func(yield func(netip.AddrPort, error) bool) {
		for _, slice := range addresses {
			for port := 1; port <= 65535; port++ {
				ap := netip.AddrPortFrom(slice, uint16(port))
				if !yield(ap, nil) {
					return
				}
			}
		}
	}
}
