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

	if isTLS, nbuf := nextIf(buf, "TLS"); isTLS {
		protocol = "TLS"
		buf = nbuf
	} else {
		return zero, fmt.Errorf("unsupported cipher suite prefix in %q", name)
	}

	var tok string
	tok, buf = next(buf)
	switch tok {
	case "AEGIS":
	case "AES":
	case "CHACHA20":
	case "DH":
	case "DHE":
	case "ECCPWD":
	case "ECDH":
	case "ECDHE":
	case "EMPTY":
	case "FALLBACK":
	case "GOSTR341112":
	case "KRB5":
	case "NULL":
	case "PSK":
	case "RSA":
		return handleRSA(buf)
	case "SHA256":
	case "SHA384":
	case "SM4":
	case "SRP":
	default:
		return zero, fmt.Errorf("unknown tok %q, %q", tok, string(buf))
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

/*
 */
func handleRSA(buf []byte) (CipherSuite, error) {
	var zero CipherSuite
	if isWith, nbuf := nextIf(buf, "WITH"); isWith {
		buf = nbuf
	} else {
		return zero, fmt.Errorf("expected WITH in %q", string(buf))
	}
	cipher, buf := next(buf)

	var keylen, mode, hash string
	switch cipher {
	case "RC4":
		if !bytes.Equal(buf, []byte("128_SHA")) {
			return zero, fmt.Errorf("unsupported %s cipher variant %q", cipher, string(buf))
		}
		keylen, mode, hash = "128", "", "SHA"
	case "3DES":
		if !bytes.Equal(buf, []byte("EDE_CBC_SHA")) {
			return zero, fmt.Errorf("unsupported %s cipher variant %q", cipher, string(buf))
		}
		keylen, mode, hash = "", "EDE_CBC", "SHA"
	case "AES":
		keylen, buf := next(buf)
		switch keylen {
		case "128":
			// TODO - allowed are
			// CBC_SHA
			// CBC_SHA256
			// GCM_SHA256
		case "256":
			// 256_CBC_SHA
			// 256_GCM_SHA384
		default:
			return zero, fmt.Errorf("unsupported %s cipher keylen %s %q", cipher, keylen, string(buf))
		}
	default:
		return zero, fmt.Errorf("unknown cipher %s, %q", cipher, string(buf))
	}
	return CipherSuite{
		Protocol: "TLS",
		KexAuth:  "RSA",
		Cipher:   cipher,
		KeyLen:   keylen,
		Mode:     mode,
		Hash:     hash,
	}, nil
}

// return next "token" and a remainder
func next(buf []byte) (string, []byte) {
	i := bytes.IndexByte(buf, '_')
	if i == -1 {
		return "", nil
	}
	return string(buf[:i]), buf[i+1:]
}

func nextIf(buf []byte, token string) (bool, []byte) {
	read, ret := next(buf)
	if read == token {
		return true, ret
	}
	return false, buf
}
