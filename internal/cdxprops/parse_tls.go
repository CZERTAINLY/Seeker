package cdxprops

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

func ParseCipherSuite(name string) (CipherSuite, error) {
	var zero CipherSuite

	// fallback names
	switch name {
	case "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":
		name = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	case "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":
		name = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	}

	var buf = []byte(name)

	if isTLS, nbuf := nextIf(buf, "TLS"); isTLS {
		buf = nbuf
	} else {
		return zero, fmt.Errorf("unsupported cipher suite prefix in %q", name)
	}

	var tok string
	tok, buf = next(buf)
	switch tok {
	case "AES":
		fallthrough
	case "CHACHA20":
		return handleTLS13(tok, buf)
	case "ECDHE":
		return handleECDHE(buf)
	case "RSA":
		return handleRSA(buf)
	}
	return zero, fmt.Errorf("unsupported TLS cipher %q, %q", tok, string(buf))
}

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
		rest := string(buf)
		switch keylen {
		case "128":
			switch rest {
			case "CBC_SHA":
				mode, hash = "CBC", "SHA"
			case "CBC_SHA256":
				mode, hash = "CBC", "SHA256"
			case "GCM_SHA256":
				mode, hash = "GCM", "SHA256"
			default:
				return zero, fmt.Errorf("unsupported %s cipher key len %s mode_hash %q", keylen, cipher, rest)
			}
		case "256":
			switch rest {
			case "CBC_SHA":
				mode, hash = "CBC", "SHA"
			case "GCM_SHA384":
				mode, hash = "GCM", "SHA384"
			default:
				return zero, fmt.Errorf("unsupported %s cipher key len %s mode_hash %q", keylen, cipher, rest)
			}
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

func handleECDHE(buf []byte) (CipherSuite, error) {
	var zero CipherSuite
	var kexAuth = "ECDHE"
	kexPart, buf := next(buf)
	switch kexPart {
	case "ECDSA":
		fallthrough
	case "RSA":
		kexAuth += "_" + kexPart
	default:
		return zero, fmt.Errorf("unsupported ECDHE_%s key exchange variant %q", kexAuth, string(buf))
	}

	if ok, nbuf := nextIf(buf, "WITH"); ok {
		buf = nbuf
	} else {
		return zero, fmt.Errorf("expected WITH in %q", string(buf))
	}

	var cipher, keylen, mode, hash string
	rest := string(buf)
	switch kexPart {
	case "ECDSA":
		switch rest {
		case "AES_128_CBC_SHA":
			cipher, keylen, mode, hash = "AES", "128", "CBC", "SHA"
		case "AES_128_CBC_SHA256":
			cipher, keylen, mode, hash = "AES", "128", "CBC", "SHA256"
		case "AES_128_GCM_SHA256":
			cipher, keylen, mode, hash = "AES", "128", "GCM", "SHA256"
		case "AES_256_CBC_SHA":
			cipher, keylen, mode, hash = "AES", "256", "CBC", "SHA"
		case "AES_256_GCM_SHA384":
			cipher, keylen, mode, hash = "AES", "256", "GCM", "SHA384"
		case "CHACHA20_POLY1305_SHA256":
			cipher, keylen, mode, hash = "CHACHA20", "", "POLY1305", "SHA256"
		case "RC4_128_SHA":
			cipher, keylen, mode, hash = "RC4", "128", "", "SHA"
		default:
			return zero, fmt.Errorf("unsupported %q", rest)
		}
	case "RSA":
	case "3DES_EDE_CBC_SHA":
		cipher, keylen, mode, hash = "3DES", "", "EDE_CBC", "SHA"
	case "AES_128_CBC_SHA":
		cipher, keylen, mode, hash = "AES", "128", "CBC", "SHA"
	case "AES_128_CBC_SHA256":
		cipher, keylen, mode, hash = "AES", "128", "CBC", "SHA256"
	case "AES_128_GCM_SHA256":
		cipher, keylen, mode, hash = "AES", "128", "GCM", "SHA256"
	case "AES_256_CBC_SHA":
		cipher, keylen, mode, hash = "AES", "256", "CBC", "SHA"
	case "AES_256_GCM_SHA384":
		cipher, keylen, mode, hash = "AES", "256", "GCM", "SHA384"
	case "CHACHA20_POLY1305_SHA256":
		cipher, keylen, mode, hash = "CHACHA20", "", "POLY1305", "SHA256"
	case "RC4_128_SHA":
		cipher, keylen, mode, hash = "RC4", "128", "", "SHA"
	default:
		return zero, fmt.Errorf("unsupported ECDHE_%s key exchange variant %q", kexAuth, string(buf))
	}

	return CipherSuite{
		Protocol: "TLS",
		KexAuth:  kexAuth,
		Cipher:   cipher,
		KeyLen:   keylen,
		Mode:     mode,
		Hash:     hash,
	}, nil
}

func handleTLS13(cipher string, buf []byte) (CipherSuite, error) {
	var zero CipherSuite
	var keylen, mode, hash string
	switch cipher + "_" + string(buf) {
	case "AES_128_GCM_SHA256":
		cipher, keylen, mode, hash = "AES", "128", "CBC", "SHA256"
	case "AES_256_GCM_SHA384":
		cipher, keylen, mode, hash = "AES", "128", "CBC", "SHA384"
	case "CHACHA20_POLY1305_SHA256":
		cipher, keylen, mode, hash = "CHACHA20", "", "POLY1305", "SHA256"
	default:
		return zero, fmt.Errorf("unsupported %q", string(buf))
	}

	return CipherSuite{
		Protocol: "TLS",
		KexAuth:  "", // empty for TLS1.3
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
