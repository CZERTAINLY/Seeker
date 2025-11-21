package cdxtest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ssh"
	"software.sslmate.com/src/go-pkcs12"
)

// Password is a Password used for PKCS#12, JKS and other keystores
const Password = "changeit" // NOSONAR - test fixture password, never used in production

type CertBuilder struct {
	keyUsage x509.KeyUsage
	isCA     bool
	algo     x509.SignatureAlgorithm
}

type SelfSignedCert struct {
	Der  []byte
	Cert *x509.Certificate
	Key  crypto.PrivateKey
}

func (c CertBuilder) WithKeyUsage(keyUsage x509.KeyUsage) CertBuilder {
	c.keyUsage = keyUsage
	return c
}

func (c CertBuilder) WithIsCA(isCA bool) CertBuilder {
	c.isCA = isCA
	return c
}

func (c CertBuilder) WithSignatureAlgorithm(algo x509.SignatureAlgorithm) CertBuilder {
	c.algo = algo
	return c
}

// GenSelfSignedCert generates a RSA self-signed certificate with default parameters.
// Use CertBuilder directly if you need to customize key usage, CA status, or signature algorithm.
func GenSelfSignedCert() (SelfSignedCert, error) {
	return CertBuilder{}.Generate()
}

// Generate generates a self-signed certificate for testing with the configured parameters.
// Defaults to RSA if no signature algorithm is specified.
func (b CertBuilder) Generate() (SelfSignedCert, error) {
	var ret SelfSignedCert
	if int(b.algo) == 0 {
		b.algo = x509.SHA256WithRSA
	}

	var keyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	if b.keyUsage != 0 {
		keyUsage = b.keyUsage
	}

	var key crypto.PrivateKey
	var publicKey crypto.PublicKey

	// Generate appropriate key type based on signature algorithm
	switch b.algo {
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return ret, err
		}
		key = ecKey
		publicKey = &ecKey.PublicKey
	case x509.PureEd25519:
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return ret, err
		}
		key = privKey
		publicKey = pubKey
	default:
		// RSA for all RSA-based algorithms and unknown/default cases
		rsaKey, err := GenRSAPrivateKey(2048)
		if err != nil {
			return ret, err
		}
		key = rsaKey
		publicKey = &rsaKey.PublicKey
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return SelfSignedCert{}, err
	}
	hash := sha1.Sum(pubKeyBytes) // NOSONAR - sha1 is fine in this context
	subjectKeyId := hash[:]

	templ := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Test Cert"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  b.isCA,
		SubjectKeyId:          subjectKeyId,
		SignatureAlgorithm:    b.algo,
	}

	der, err := x509.CreateCertificate(rand.Reader, templ, templ, publicKey, key)
	if err != nil {
		return ret, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ret, err
	}
	return SelfSignedCert{
		Der:  der,
		Cert: cert,
		Key:  key,
	}, nil
}

func (s SelfSignedCert) PublicKey() crypto.PublicKey {
	return s.Cert.PublicKey
}

// CertPEM encodes certificate in PEM format
func (s SelfSignedCert) CertPEM() ([]byte, error) {
	var buf bytes.Buffer
	err := pem.Encode(&buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.Der,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encode certificate: %w", err)
	}
	return buf.Bytes(), nil
}

// PrivKeyMarshal marshals a private key to its appropriate format (PKCS#1 for RSA, SEC1 for ECDSA, PKCS#8 for others)
func (s SelfSignedCert) PrivKeyMarshal() ([]byte, error) {
	switch k := s.Key.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(k), nil
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(k)
	case ed25519.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(k)
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", s.Key)
	}
}

func (s SelfSignedCert) PrivKeyPEM() ([]byte, error) {
	var block *pem.Block

	switch s.Key.(type) {
	case *rsa.PrivateKey:
		block = &pem.Block{
			Type: "RSA PRIVATE KEY",
		}
	case *ecdsa.PrivateKey:
		block = &pem.Block{
			Type: "EC PRIVATE KEY",
		}
	case ed25519.PrivateKey:
		block = &pem.Block{
			Type: "PRIVATE KEY",
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", s.Key)
	}

	var buf bytes.Buffer
	b, err := s.PrivKeyMarshal()
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}
	block.Bytes = b
	err = pem.Encode(&buf, block)
	if err != nil {
		return nil, fmt.Errorf("encoding private key: %w", err)
	}
	return buf.Bytes(), nil
}

// PKCS12 creates PKCS#12 with certificate and private key
func (s SelfSignedCert) PKCS12() ([]byte, error) {
	return pkcs12.LegacyRC2.Encode(s.Key, s.Cert, nil, Password)
}

func GenRSAPrivateKey(size int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, size)
}

// GenECPrivateKey generates an ECDSA private key for testing
func GenECPrivateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	if curve == nil {
		return nil, errors.New("curve is nil")
	}
	return ecdsa.GenerateKey(curve, rand.Reader)
}

// GenEd25519Keys generates an Ed25519 private key for testing
func GenEd25519Keys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// GenCSR generates a certificate signing request for testing
func GenCSR(key crypto.PrivateKey) (*x509.CertificateRequest, []byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Test CSR",
			Organization: []string{"Test Org"},
		},
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, nil, err
	}

	csr, err := x509.ParseCertificateRequest(der)
	return csr, der, err
}

// GenCRL generates a certificate revocation list for testing
func GenCRL(cert *x509.Certificate, priv crypto.Signer) (*x509.RevocationList, []byte, error) {
	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificates: []pkix.RevokedCertificate{
			{
				SerialNumber:   big.NewInt(42),
				RevocationTime: time.Now(),
			},
		},
	}

	der, err := x509.CreateRevocationList(rand.Reader, template, cert, priv)
	if err != nil {
		return nil, nil, err
	}

	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated CRL: %w", err)
	}
	return crl, der, nil
}

// GenOpenSSHPrivateKey generates an OpenSSH format private key for testing
func GenOpenSSHPrivateKey() (ed25519.PrivateKey, []byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Marshal to OpenSSH format
	pemBytes, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, nil, err
	}

	return priv, pem.EncodeToMemory(pemBytes), nil
}
