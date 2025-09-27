package main

import (
	"bytes"
	"fmt"
)

type CipherSuite struct {
	Protocol string
	KexAuth  string // may be empty in TLS 1.3
	Cipher   string
	KeyLen   string
	Mode     string
	Hash     string
}

// TLS 1.2 and earlier: TLS_<KEX[_AUTH]>[_EXPORT]_WITH_<CIPHER>_<KEYLEN>_<MODE?>_<HASH>

// TLS 1.3: TLS_<CIPHER>_<KEYLEN>_<MODE>_<HASH>
// Example: TLS_AES_128_GCM_SHA256
// Example: TLS_CHACHA20_POLY1305_SHA256
func ParseCipherSuite(name string) (CipherSuite, error) {
	var zero CipherSuite
	var protocol string

	var buf = []byte(name)
	if hasPrefix(buf, "TLS_") {
		protocol = "TLS"
		buf = buf[4:]
	} else {
		return zero, fmt.Errorf("unsupported cipher suite prefix in %q", name)
	}

	tok, i := next(buf)
	switch tok {
	case "NULL":
	// TODO
	case "RSA":
	//TODO
	case "DH":
	//TODO
	case "DHE":
	//TODO
	case "KRB5":
	//TODO
	case "PSK":
	// TODO
	case "SM4":
	case "EMPTY":
	case "AES":
	case "CHACHA20":
	case "AEGIS":
	case "FALLBACK":
	case "ECDH":
	case "ECDHE":
	case "SRP":
	case "ECCPWD":
	case "SHA256":
	case "SHA384":
	case "GOSTR341112":
	default:
		return zero, fmt.Errorf("unknown tok %q, %d", tok, i)
	}

	return CipherSuite{
		Protocol: protocol,
		KexAuth:  tok, // todo this is wrong, just a debug out
		Cipher:   "n/a",
		KeyLen:   "n/a",
		Mode:     "n/a",
		Hash:     "n/a",
	}, nil
}

func hasPrefix(buf []byte, prefix string) bool {
	return bytes.HasPrefix(buf, []byte(prefix))
}

// return next "token" and a slice index
func next(buf []byte) (string, int) {
	i := bytes.IndexByte(buf, '_')
	if i == -1 {
		return "", -1
	}
	return string(buf[:i]), i
}
