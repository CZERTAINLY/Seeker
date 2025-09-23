//go:build !linux

package netscan

import (
	"errors"
	"iter"
	"net/netip"
)

func LocalPortsNetlink() (iter.Seq[netip.AddrPort], error) {
	return nil, errors.New("LocalPortsNetlink is available only on Linux")
}
