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
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ssh"
)

type CertBuilder struct {
	keyUsage x509.KeyUsage
	isCA     bool
}

type SelfSignedCert struct {
	Der  []byte
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

func (c CertBuilder) WithKeyUsage(keyUsage x509.KeyUsage) CertBuilder {
	c.keyUsage = keyUsage
	return c
}

func (c CertBuilder) WithIsCA(isCA bool) CertBuilder {
	c.isCA = isCA
	return c
}

func GenSelfSignedCert() (SelfSignedCert, error) {
	return CertBuilder{}.Generate()
}

// GenSelfSignedCert generates a RSA self-signed certificate for testing
func (b CertBuilder) Generate() (SelfSignedCert, error) {
	var ret SelfSignedCert

	var keyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	if b.keyUsage != 0 {
		keyUsage = b.keyUsage
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ret, err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return SelfSignedCert{}, err
	}
	hash := sha1.Sum(pubKeyBytes)
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
	}

	der, err := x509.CreateCertificate(rand.Reader, templ, templ, &key.PublicKey, key)
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

// PrivKeyPEM encodes private key in PEM format
func (s SelfSignedCert) PrivKeyPEM() ([]byte, error) {
	var buf bytes.Buffer
	err := pem.Encode(&buf, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(s.Key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}
	return buf.Bytes(), nil
}

// GenECPrivateKey generates an ECDSA private key for testing
func GenECPrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenEd25519PrivateKey generates an Ed25519 private key for testing
func GenEd25519PrivateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
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

// EncodePKCS8 encodes a private key to PKCS#8 format
func EncodePKCS8(key crypto.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}

// EncodePKCS1 encodes an RSA private key to PKCS#1 format
func EncodePKCS1(key *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(key)
}

// EncodeECPrivateKey encodes an ECDSA private key to SEC1 format
func EncodeECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalECPrivateKey(key)
}
