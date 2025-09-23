package netscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2"
)

type Result struct {
	State        tls.ConnectionState
	Log          *zgrab2.TLSLog
	HandshakeLog *tls.ServerHandshake
}

func InspectTLS(ctx context.Context, addrPort netip.AddrPort) (Result, error) {
	// dial TCP first
	conn, err := net.DialTimeout("tcp", addrPort.String(), 5*time.Second)
	if err != nil {
		return Result{}, fmt.Errorf("dial: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	var tlsFlags zgrab2.TLSFlags
	wrapper := zgrab2.GetDefaultTLSWrapper(&tlsFlags)
	target := &zgrab2.ScanTarget{
		IP:   addrPort.Addr().AsSlice(),
		Port: uint(addrPort.Port()),
	}

	// Upgrade the connection (context with timeout)
	connCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	tlsConn, err := wrapper(connCtx, target, conn)
	if err != nil {
		return Result{}, fmt.Errorf("zgrab2 GetDefaultTLS: %w", err)
	}

	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("zgrab2: tls Handshake: %w", err)
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return Result{}, model.ErrNoMatch
	}

	tlsConn.GetHandshakeLog()

	return Result{
		State:        state,
		Log:          tlsConn.GetLog(),
		HandshakeLog: tlsConn.GetHandshakeLog(),
	}, nil
}
