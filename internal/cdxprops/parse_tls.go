package cdxprops

import (
	"bytes"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type Protocol uint8

const (
	ProtocolUnknown = iota
	SSL
	TLS
)

type KeyExchangeAlgorithm string

const (
	KexDHE   = "DHE"
	KexECDHE = "ECDHE"
	KexRSA   = "RSA"
)

type KeyAuthenticationAlgorithm string

const (
	KauthEmpty = ""
	KauthECDSA = "ECDSA"
	KauthRSA   = "RSA"
)

type KeyExchange struct {
	Exchange KeyExchangeAlgorithm
	Auth     KeyAuthenticationAlgorithm
}

type CipherAlgorithm string

const (
	CipherUnknown  = "UNKNOWN"
	CipherRC4      = "RC4"
	Cipher3DES     = "3DES"
	CipherAES      = "AES"
	CipherCHACHA20 = "CHACHA20"
)

type KeyLen int

const (
	KeyLenUnspecified = 0
	KeyLen128         = 128
	KeyLen256         = 256
)

type CipherMode string

const (
	CipherModeCBC      = "CBC"
	CipherModeCCM      = "CCM"
	CipherModeEDE_CBC  = "EDE_CBC"
	CipherModeEmpty    = ""
	CipherModeGCM      = "GCM"
	CipherModePOLY1305 = "POLY1305"
	CipherModeUnknown  = "UNKNOWN"
)

type HashAlgorithm string

const (
	HashSHA    = "SHA"
	HashSHA256 = "SHA256"
	HashSHA384 = "SHA384"
)

type CipherSuite struct {
	Name        string // this is name after all fallbacks are processed
	Protocol    Protocol
	KeyExchange KeyExchange
	Cipher      CipherAlgorithm
	KeyLen      KeyLen
	Mode        CipherMode
	Hash        HashAlgorithm
	Code        CipherSuiteCode
}

// Algorithms returns a list of algorithm identifiers for the cipher suite.
func (c CipherSuite) Algorithms() []cdx.BOMReference {
	var ret []cdx.BOMReference
	add := func(s string) {
		ret = append(ret, cdx.BOMReference(s))
	}
	switch c.KeyExchange.Exchange {
	case KexDHE:
		add("crypto/algorithm/dhe@1.2.840.10046.2.1")    // ANSI X9.42 dhpublicnumber
		add("crypto/algorithm/dhe@1.2.840.113549.1.3.1") // PKCS#3 dkKeyAgreement
	case KexRSA:
		add("crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1")
	case KexECDHE:
		add("crypto/algorithm/ecdh-curve25519@1.3.132.1.12")
	}

	switch c.KeyExchange.Auth {
	case KauthECDSA:
		add("crypto/algorithm/ecdsa@1.2.840.10045.4.3.2")
	case KauthRSA:
		add("crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1")
	}

	// Cipher + KeyLen + Mode
	switch {
	case c.Cipher == CipherRC4 && c.KeyLen == KeyLen128:
		add("crypto/algorithm/rc4-128@1.2.840.113549.3.4")
	case c.Cipher == Cipher3DES && c.Mode == CipherModeEDE_CBC:
		add("crypto/algorithm/3des-ede-cbc@1.2.840.113549.3.7")
	case c.Cipher == CipherAES && c.KeyLen == KeyLen128 && c.Mode == CipherModeCBC:
		add("crypto/algorithm/aes-128-cbc@2.16.840.1.101.3.4.1.2")
	case c.Cipher == CipherAES && c.KeyLen == KeyLen256 && c.Mode == CipherModeCBC:
		add("crypto/algorithm/aes-256-cbc@2.16.840.1.101.3.4.1.42")
	case c.Cipher == CipherAES && c.KeyLen == KeyLen128 && c.Mode == CipherModeGCM:
		add("crypto/algorithm/aes-128-gcm@2.16.840.1.101.3.4.1.6")
	case c.Cipher == CipherAES && c.KeyLen == KeyLen256 && c.Mode == CipherModeGCM:
		add("crypto/algorithm/aes-256-gcm@2.16.840.1.101.3.4.1.46")
	case c.Cipher == CipherCHACHA20 && c.Mode == CipherModePOLY1305:
		add("crypto/algorithm/chacha20-poly1305@ietf-rfc8439")
	}

	switch c.Hash {
	case HashSHA:
		add("crypto/algorithm/sha-1@1.3.14.3.2.26")
	case HashSHA256:
		add("crypto/algorithm/sha-256@2.16.840.1.101.3.4.2.1")
	case HashSHA384:
		add("crypto/algorithm/sha-384@2.16.840.1.101.3.4.2.2")
	}

	return ret
}

var _fallbackNames = map[string]string{
	// defined in Go crypto/tls
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	// openssl compat names for TLS 1.3
	"TLS_AKE_WITH_AES_128_GCM_SHA256":       "TLS_AES_128_GCM_SHA256",
	"TLS_AKE_WITH_AES_256_GCM_SHA384":       "TLS_AES_256_GCM_SHA384",
	"TLS_AKE_WITH_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256",
}

// ParseCipherSuite parses a TLS cipher suite name into its components.
func ParseCipherSuite(name string) (CipherSuite, error) {
	var ret CipherSuite

	// fallback names
	if fallback, ok := _fallbackNames[name]; ok {
		name = fallback
	}

	var buf = []byte(name)

	if isTLS, nbuf := nextIf(buf, "TLS"); isTLS {
		buf = nbuf
	} else {
		return ret, fmt.Errorf("unsupported cipher suite prefix in %q", name)
	}

	var err error
	var tok string
	tok, buf = next(buf)
	switch tok {
	case "AES":
		ret, err = handleTLS13(CipherAES, buf)
	case "CHACHA20":
		ret, err = handleTLS13(CipherCHACHA20, buf)
	case "DHE":
		ret, err = handleDHE(buf)
	case "ECDHE":
		ret, err = handleECDHE(buf)
	case "RSA":
		ret, err = handleRSA(buf)
	default:
		return ret, fmt.Errorf("unsupported TLS cipher %q, %q", tok, string(buf))
	}
	if err != nil {
		return ret, err
	}

	code, ok := Code(name)
	if !ok {
		return ret, fmt.Errorf("unknown code for %q", name)
	}
	ret.Name = name
	ret.Code = code
	return ret, nil
}

func handleRSA(buf []byte) (CipherSuite, error) {
	var zero CipherSuite
	if isWith, nbuf := nextIf(buf, "WITH"); isWith {
		buf = nbuf
	} else {
		return zero, fmt.Errorf("expected WITH in %q", string(buf))
	}
	cipherToken, buf := next(buf)

	var cipher CipherAlgorithm
	var keylen KeyLen
	var mode CipherMode
	var hash HashAlgorithm
	switch cipherToken {
	case "RC4":
		if !bytes.Equal(buf, []byte("128_SHA")) {
			return zero, fmt.Errorf("unsupported %s cipher variant %q", cipherToken, string(buf))
		}
		cipher, keylen, mode, hash = CipherRC4, KeyLen128, CipherModeEmpty, HashSHA
	case "3DES":
		if !bytes.Equal(buf, []byte("EDE_CBC_SHA")) {
			return zero, fmt.Errorf("unsupported %s cipher variant %q", cipherToken, string(buf))
		}
		cipher, keylen, mode, hash = Cipher3DES, 0, CipherModeEDE_CBC, HashSHA
	case "AES":
		cipher = CipherAES
		keylen, buf := next(buf)
		rest := string(buf)
		switch keylen {
		case "128":
			switch rest {
			case "CBC_SHA":
				mode, hash = CipherModeCBC, "SHA"
			case "CBC_SHA256":
				mode, hash = CipherModeCBC, "SHA256"
			case "GCM_SHA256":
				mode, hash = CipherModeGCM, "SHA256"
			default:
				return zero, fmt.Errorf("unsupported %s cipher key len %s mode_hash %q", keylen, cipherToken, rest)
			}
		case "256":
			switch rest {
			case "CBC_SHA":
				mode, hash = CipherModeCBC, "SHA"
			case "GCM_SHA384":
				mode, hash = CipherModeGCM, "SHA384"
			default:
				return zero, fmt.Errorf("unsupported %s cipher key len %s mode_hash %q", keylen, cipherToken, rest)
			}
		default:
			return zero, fmt.Errorf("unsupported %s cipher keylen %s %q", cipherToken, keylen, string(buf))
		}
	default:
		return zero, fmt.Errorf("unknown cipher %s, %q", cipherToken, string(buf))
	}
	return CipherSuite{
		Protocol:    TLS,
		KeyExchange: KeyExchange{Exchange: KexRSA},
		Cipher:      cipher,
		KeyLen:      keylen,
		Mode:        mode,
		Hash:        hash,
	}, nil
}

func handleDHE(buf []byte) (CipherSuite, error) {
	var zero CipherSuite
	var keyExchange KeyExchange
	kexPart, buf := next(buf)
	switch kexPart {
	case "RSA":
		keyExchange = KeyExchange{Exchange: KexDHE, Auth: KauthRSA}
	default:
		return zero, fmt.Errorf("unsupported DHE%s key exchange variant %q", kexPart, string(buf))
	}

	if ok, nbuf := nextIf(buf, "WITH"); ok {
		buf = nbuf
	} else {
		return zero, fmt.Errorf("expected WITH in %q", string(buf))
	}

	var cipher CipherAlgorithm
	var keylen KeyLen
	var mode CipherMode
	var hash HashAlgorithm
	var err error
	rest := string(buf)
	switch kexPart {
	case "RSA":
		allowed := map[string]struct{}{
			"AES_128_CBC_SHA":          {},
			"AES_128_CBC_SHA256":       {},
			"AES_128_GCM_SHA256":       {},
			"AES_256_CBC_SHA":          {},
			"AES_256_CBC_SHA256":       {},
			"AES_256_GCM_SHA384":       {},
			"CHACHA20_POLY1305_SHA256": {},
		}
		cipher, keylen, mode, hash, err = handleRest(allowed, rest)
		if err != nil {
			return zero, err
		}
	default:
		return zero, fmt.Errorf("unsupported DHE_%s key exchange variant %q", kexPart, string(buf))
	}

	return CipherSuite{
		Protocol:    TLS,
		KeyExchange: keyExchange,
		Cipher:      cipher,
		KeyLen:      keylen,
		Mode:        mode,
		Hash:        hash,
	}, nil

}

func handleECDHE(buf []byte) (CipherSuite, error) {
	var zero CipherSuite
	var keyExchange KeyExchange
	kexPart, buf := next(buf)
	switch kexPart {
	case "ECDSA":
		keyExchange = KeyExchange{Exchange: KexECDHE, Auth: KauthECDSA}
	case "RSA":
		keyExchange = KeyExchange{Exchange: KexECDHE, Auth: KauthRSA}
	default:
		return zero, fmt.Errorf("unsupported ECDHE_%s key exchange variant %q", kexPart, string(buf))
	}

	if ok, nbuf := nextIf(buf, "WITH"); ok {
		buf = nbuf
	} else {
		return zero, fmt.Errorf("expected WITH in %q", string(buf))
	}

	var cipher CipherAlgorithm
	var keylen KeyLen
	var mode CipherMode
	var hash HashAlgorithm
	var err error
	rest := string(buf)
	switch kexPart {
	case "ECDSA":
		allowed := map[string]struct{}{
			"AES_128_CBC_SHA":          {},
			"AES_128_CBC_SHA256":       {},
			"AES_128_GCM_SHA256":       {},
			"AES_256_CBC_SHA":          {},
			"AES_256_CBC_SHA256":       {},
			"AES_256_GCM_SHA384":       {},
			"CHACHA20_POLY1305_SHA256": {},
			"RC4_128_SHA":              {},
		}
		cipher, keylen, mode, hash, err = handleRest(allowed, rest)
		if err != nil {
			return zero, err
		}
	case "RSA":
		allowed := map[string]struct{}{
			"3DES_EDE_CBC_SHA":         {},
			"AES_128_CBC_SHA":          {},
			"AES_128_CBC_SHA256":       {},
			"AES_128_GCM_SHA256":       {},
			"AES_256_CBC_SHA":          {},
			"AES_256_CBC_SHA384":       {},
			"AES_256_GCM_SHA384":       {},
			"CHACHA20_POLY1305_SHA256": {},
			"RC4_128_SHA":              {},
		}
		cipher, keylen, mode, hash, err = handleRest(allowed, rest)
		if err != nil {
			return zero, err
		}
	default:
		return zero, fmt.Errorf("unsupported ECDHE_%s key exchange variant %q", kexPart, string(buf))
	}

	return CipherSuite{
		Protocol:    TLS,
		KeyExchange: keyExchange,
		Cipher:      cipher,
		KeyLen:      keylen,
		Mode:        mode,
		Hash:        hash,
	}, nil
}

func handleTLS13(cipher CipherAlgorithm, buf []byte) (CipherSuite, error) {
	var zero CipherSuite
	var keylen KeyLen
	var mode CipherMode
	var hash HashAlgorithm
	var err error
	rest := string(cipher) + "_" + string(buf)

	allowed := map[string]struct{}{
		"AES_128_GCM_SHA256":       {},
		"AES_256_GCM_SHA384":       {},
		"CHACHA20_POLY1305_SHA256": {},
	}
	cipher, keylen, mode, hash, err = handleRest(allowed, rest)
	if err != nil {
		return zero, err
	}

	return CipherSuite{
		Protocol: TLS,
		// KeyAuth is not applicable in TLS 1.3
		Cipher: cipher,
		KeyLen: keylen,
		Mode:   mode,
		Hash:   hash,
	}, nil
}

func handleRest(allowed map[string]struct{}, rest string) (CipherAlgorithm, KeyLen, CipherMode, HashAlgorithm, error) {
	var cipher CipherAlgorithm
	var keylen KeyLen
	var mode CipherMode
	var hash HashAlgorithm

	if _, ok := allowed[rest]; !ok {
		return cipher, keylen, mode, hash, fmt.Errorf("unsupported %q", rest)
	}

	switch rest {
	case "3DES_EDE_CBC_SHA":
		cipher, keylen, mode, hash = Cipher3DES, 0, "EDE_CBC", "SHA"
	case "AES_128_CBC_SHA":
		cipher, keylen, mode, hash = CipherAES, KeyLen128, CipherModeCBC, "SHA"
	case "AES_128_CBC_SHA256":
		cipher, keylen, mode, hash = CipherAES, KeyLen128, CipherModeCBC, "SHA256"
	case "AES_128_GCM_SHA256":
		cipher, keylen, mode, hash = CipherAES, KeyLen128, CipherModeGCM, "SHA256"
	case "AES_256_CBC_SHA":
		cipher, keylen, mode, hash = CipherAES, KeyLen256, CipherModeCBC, "SHA"
	case "AES_256_CBC_SHA256":
		cipher, keylen, mode, hash = CipherAES, KeyLen256, CipherModeCBC, "SHA256"
	case "AES_256_CBC_SHA384":
		cipher, keylen, mode, hash = CipherAES, KeyLen256, CipherModeCBC, "SHA384"
	case "AES_256_GCM_SHA384":
		cipher, keylen, mode, hash = CipherAES, KeyLen256, CipherModeGCM, "SHA384"
	case "CHACHA20_POLY1305_SHA256":
		cipher, keylen, mode, hash = CipherCHACHA20, 0, CipherModePOLY1305, "SHA256"
	case "RC4_128_SHA":
		cipher, keylen, mode, hash = CipherRC4, KeyLen128, "", "SHA"
	default:
		return cipher, keylen, mode, hash, fmt.Errorf("unsupported %q", rest)
	}

	return cipher, keylen, mode, hash, nil
}

// return next "token" and a remainder
func next(buf []byte) (string, []byte) {
	i := bytes.IndexByte(buf, '_')
	if i == -1 {
		return string(buf), nil
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
