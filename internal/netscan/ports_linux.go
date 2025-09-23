package netscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"iter"
	"net"
	"net/netip"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// LocalPortsNetlink dumps opened ports directly from Linux kernel via netlink interface.
// It errors in case netlink is not accessible or system is not Linux. In this case is caller
// supposed to use LocalPortsDial fallback.
func LocalPortsNetlink() (iter.Seq[netip.AddrPort], error) {
	fours, err := ss(false)
	if err != nil {
		return nil, fmt.Errorf("dump socket statistics for ipv4: %w", err)
	}
	sixs, err := ss(true)
	if err != nil {
		return nil, fmt.Errorf("dump socket statistics for ipv6: %w", err)
	}

	return func(yield func(netip.AddrPort) bool) {
		for _, a4 := range fours {
			if !yield(a4) {
				return
			}
		}
		for _, a6 := range sixs {
			if !yield(a6) {
				break
			}
		}
	}, nil
}

// Constants from linux headers.
const (
	// Netlink family for socket diagnostics.
	NETLINK_SOCK_DIAG = 4

	// Message type: request sockets by family.
	SOCK_DIAG_BY_FAMILY = 20

	// Protocol
	IPPROTO_TCP = 6

	// TCP socket state from include/net/tcp_states.h in the Linux kernel.
	TCP_LISTEN = 10

	// inet_diag_req_v2 idiag_states bitmask
	TCPF_LISTEN = 1 << TCP_LISTEN
)

// inet_diag_req_v2 structure (from linux/inet_diag.h).
type inetDiagReqV2 struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	Pad      uint8
	States   uint32
	ID       inetDiagSockID
}

type inetDiagSockID struct {
	SPort  [2]byte
	DPort  [2]byte
	Src    [16]byte
	Dst    [16]byte
	If     uint32
	Cookie [2]uint32
}

// inet_diag_msg (reply)
type inetDiagMsg struct {
	Family  uint8
	State   uint8
	Timer   uint8
	Retrans uint8
	ID      inetDiagSockID
	Expires uint32
	Rqueue  uint32
	Wqueue  uint32
	UID     uint32
	Inode   uint32
}

func ss(ipv6 bool) ([]netip.AddrPort, error) {
	var family uint8 = unix.AF_INET
	var iplen = 4
	if ipv6 {
		family = unix.AF_INET6
		iplen = 16
	}
	// Open a NETLINK_SOCK_DIAG connection.
	c, err := netlink.Dial(NETLINK_SOCK_DIAG, nil)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer func() {
		_ = c.Close() //nolint errcheck
	}()

	// Build request: inet_diag_req_v2
	req := inetDiagReqV2{
		Family:   family,
		Protocol: IPPROTO_TCP,
		States:   TCPF_LISTEN,
		// ID is zeroed: wildcard (match all).
	}

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.NativeEndian, req); err != nil {
		return nil, fmt.Errorf("marshal req: %w", err)
	}

	// Send netlink message
	msg := netlink.Message{
		Header: netlink.Header{
			Type:  SOCK_DIAG_BY_FAMILY,
			Flags: netlink.Request | netlink.Dump,
		},
		Data: buf.Bytes(),
	}
	msgs, err := c.Execute(msg)
	if err != nil {
		return nil, fmt.Errorf("execute: %w", err)
	}

	// Parse replies
	ret := make([]netip.AddrPort, 0, len(msgs))
	for _, m := range msgs {
		if m.Header.Type == netlink.Done {
			continue
		}
		var r inetDiagMsg
		// First 36 bytes = inet_diag_msg (for IPv4)
		if len(m.Data) < 36 {
			continue
		}
		copy(r.ID.SPort[:], m.Data[4:6])
		copy(r.ID.DPort[:], m.Data[6:8])
		copy(r.ID.Src[:4], m.Data[8:12])

		sport := binary.BigEndian.Uint16(r.ID.SPort[:])
		ip := net.IP(r.ID.Src[:iplen])
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, fmt.Errorf("invalid IP %s", ip.String())
		}
		ret = append(ret, netip.AddrPortFrom(addr, sport))
	}
	return ret, nil
}
