// human readable and writable stdlib types
// which can be used inside config file
package model

import (
	"errors"
	"net"
	"net/url"
	"os"
)

type URL struct {
	*url.URL
}

func (u URL) AsURL() *url.URL {
	return u.URL
}

func (u URL) Clone() URL {
	if u.URL == nil {
		return URL{}
	}

	clone := &url.URL{
		Scheme:      u.Scheme,
		Opaque:      u.Opaque,
		Host:        u.Host,
		Path:        u.Path,
		RawPath:     u.RawPath,
		OmitHost:    u.OmitHost,
		ForceQuery:  u.ForceQuery,
		RawQuery:    u.RawQuery,
		Fragment:    u.Fragment,
		RawFragment: u.RawFragment,
	}

	if u.User != nil {
		if password, ok := u.User.Password(); ok {
			clone.User = url.UserPassword(u.User.Username(), password)
		} else {
			clone.User = url.User(u.User.Username())
		}
	}

	return URL{URL: clone}
}

func (u *URL) UnmarshalText(text []byte) error {
	if u == nil {
		return errors.New("can't unmarshal to nil")
	}
	parsed, err := url.Parse(os.ExpandEnv(string(text)))
	if err != nil {
		return err
	}
	u.URL = parsed
	return nil
}

func (u URL) MarshalText() ([]byte, error) {
	if u.URL == nil {
		return []byte{}, nil
	}
	return []byte(u.String()), nil
}

type TCPAddr struct {
	*net.TCPAddr
}

func (addr *TCPAddr) AsTCPAddr() *net.TCPAddr {
	return addr.TCPAddr
}

func (addr *TCPAddr) UnmarshalText(text []byte) error {
	if addr == nil {
		return errors.New("can't unmarshal to nil")
	}
	if len(text) == 0 {
		return errors.New("can't be empty")
	}
	expanded := os.ExpandEnv(string(text))
	parsed, err := net.ResolveTCPAddr("tcp", expanded)
	if err != nil {
		return err
	}
	addr.TCPAddr = parsed
	return nil
}

func (addr TCPAddr) MarshalText() ([]byte, error) {
	if addr.TCPAddr == nil {
		return []byte{}, nil
	}
	return []byte(addr.String()), nil
}
