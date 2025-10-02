package cdxprops

import (
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
	Protocol    Protocol
	KeyExchange KeyExchange
	Cipher      CipherAlgorithm
	KeyLen      KeyLen
	Mode        CipherMode
	Hash        HashAlgorithm
	Name        string
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

var byCode = map[CipherSuiteCode]CipherSuite{
	// TLS 1.3 (no key exchange/auth in struct -> zero KeyExchange)
	TLS_AES_128_GCM_SHA256:       {TLS, KeyExchange{}, CipherAES, KeyLen128, CipherModeGCM, HashSHA256, "", 0},
	TLS_AES_256_GCM_SHA384:       {TLS, KeyExchange{}, CipherAES, KeyLen256, CipherModeGCM, HashSHA384, "", 0},
	TLS_CHACHA20_POLY1305_SHA256: {TLS, KeyExchange{}, CipherCHACHA20, 0, CipherModePOLY1305, HashSHA256, "", 0},

	// RSA
	TLS_RSA_WITH_RC4_128_SHA:        {TLS, KeyExchange{Exchange: KexRSA}, CipherRC4, KeyLen128, CipherModeEmpty, HashSHA, "", 0},
	TLS_RSA_WITH_3DES_EDE_CBC_SHA:   {TLS, KeyExchange{Exchange: KexRSA}, Cipher3DES, 0, CipherModeEDE_CBC, HashSHA, "", 0},
	TLS_RSA_WITH_AES_128_CBC_SHA:    {TLS, KeyExchange{Exchange: KexRSA}, CipherAES, KeyLen128, CipherModeCBC, HashSHA, "", 0},
	TLS_RSA_WITH_AES_128_CBC_SHA256: {TLS, KeyExchange{Exchange: KexRSA}, CipherAES, KeyLen128, CipherModeCBC, HashSHA256, "", 0},
	TLS_RSA_WITH_AES_128_GCM_SHA256: {TLS, KeyExchange{Exchange: KexRSA}, CipherAES, KeyLen128, CipherModeGCM, HashSHA256, "", 0},
	TLS_RSA_WITH_AES_256_CBC_SHA:    {TLS, KeyExchange{Exchange: KexRSA}, CipherAES, KeyLen256, CipherModeCBC, HashSHA, "", 0},
	TLS_RSA_WITH_AES_256_GCM_SHA384: {TLS, KeyExchange{Exchange: KexRSA}, CipherAES, KeyLen256, CipherModeGCM, HashSHA384, "", 0},

	// DHE_RSA
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA:          {TLS, KeyExchange{Exchange: KexDHE, Auth: KauthRSA}, CipherAES, KeyLen128, CipherModeCBC, HashSHA, "", 0},
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:       {TLS, KeyExchange{Exchange: KexDHE, Auth: KauthRSA}, CipherAES, KeyLen128, CipherModeCBC, HashSHA256, "", 0},
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:       {TLS, KeyExchange{Exchange: KexDHE, Auth: KauthRSA}, CipherAES, KeyLen128, CipherModeGCM, HashSHA256, "", 0},
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA:          {TLS, KeyExchange{Exchange: KexDHE, Auth: KauthRSA}, CipherAES, KeyLen256, CipherModeCBC, HashSHA, "", 0},
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:       {TLS, KeyExchange{Exchange: KexDHE, Auth: KauthRSA}, CipherAES, KeyLen256, CipherModeCBC, HashSHA256, "", 0},
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:       {TLS, KeyExchange{Exchange: KexDHE, Auth: KauthRSA}, CipherAES, KeyLen256, CipherModeGCM, HashSHA384, "", 0},
	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: {TLS, KeyExchange{Exchange: KexDHE, Auth: KauthRSA}, CipherCHACHA20, 0, CipherModePOLY1305, HashSHA256, "", 0},

	// ECDHE_ECDSA
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:          {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthECDSA}, CipherAES, KeyLen128, CipherModeCBC, HashSHA, "", 0},
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:       {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthECDSA}, CipherAES, KeyLen128, CipherModeCBC, HashSHA256, "", 0},
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthECDSA}, CipherAES, KeyLen128, CipherModeGCM, HashSHA256, "", 0},
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:          {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthECDSA}, CipherAES, KeyLen256, CipherModeCBC, HashSHA, "", 0},
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthECDSA}, CipherAES, KeyLen256, CipherModeGCM, HashSHA384, "", 0},
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthECDSA}, CipherCHACHA20, 0, CipherModePOLY1305, HashSHA256, "", 0},
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:              {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthECDSA}, CipherRC4, KeyLen128, CipherModeEmpty, HashSHA, "", 0},

	// ECDHE_RSA
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:         {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthRSA}, Cipher3DES, 0, CipherModeEDE_CBC, HashSHA, "", 0},
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:          {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthRSA}, CipherAES, KeyLen128, CipherModeCBC, HashSHA, "", 0},
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:       {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthRSA}, CipherAES, KeyLen128, CipherModeCBC, HashSHA256, "", 0},
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:       {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthRSA}, CipherAES, KeyLen128, CipherModeGCM, HashSHA256, "", 0},
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:          {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthRSA}, CipherAES, KeyLen256, CipherModeCBC, HashSHA, "", 0},
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:       {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthRSA}, CipherAES, KeyLen256, CipherModeCBC, HashSHA384, "", 0},
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:       {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthRSA}, CipherAES, KeyLen256, CipherModeGCM, HashSHA384, "", 0},
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthRSA}, CipherCHACHA20, 0, CipherModePOLY1305, HashSHA256, "", 0},
	TLS_ECDHE_RSA_WITH_RC4_128_SHA:              {TLS, KeyExchange{Exchange: KexECDHE, Auth: KauthRSA}, CipherRC4, KeyLen128, CipherModeEmpty, HashSHA, "", 0},
}

// ParseCipherSuite parses a TLS cipher suite name into its components.
// this function check fallback names and returned CipherSuite name is
// always normalized
func ParseCipherSuite(name string) (CipherSuite, bool) {
	var ret CipherSuite

	// fallback names
	if fallback, ok := _fallbackNames[name]; ok {
		name = fallback
	}

	code, ok := Code(name)
	if !ok {
		return ret, false
	}

	suite, ok := byCode[code]
	if !ok {
		return ret, false
	}

	suite.Name = name
	suite.Code = code
	return suite, true
}
