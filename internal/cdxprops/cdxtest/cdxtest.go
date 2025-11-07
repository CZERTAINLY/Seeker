package cdxtest

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type SelfSignedCert struct {
	Der  []byte
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// GenSelfSignedCert generates a self-signed certificate for testing
func GenSelfSignedCert() (SelfSignedCert, error) {
	var ret SelfSignedCert
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ret, err
	}

	templ := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Test Cert"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
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
	return buf.Bytes(), err
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

// getProp gets a property value from a CDX component
func GetProp(comp cdx.Component, name string) string {
	if comp.Properties == nil {
		return ""
	}
	for _, p := range *comp.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// HasEvidencePath checks that the component has the expected evidence path
func HasEvidencePath(comp cdx.Component) error {
	if comp.Evidence == nil {
		return fmt.Errorf("evidence is nil")
	}
	if comp.Evidence.Occurrences == nil {
		return fmt.Errorf("evidence occurrences is nil")
	}
	if len(*comp.Evidence.Occurrences) < 1 {
		return fmt.Errorf("evidence occurrences is empty")
	}

	loc := (*comp.Evidence.Occurrences)[0].Location
	if loc == "" {
		return fmt.Errorf("location is empty")
	}

	abs, err := filepath.Abs("testpath")
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	if !filepath.IsAbs(loc) {
		return fmt.Errorf("location path is not absolute: %s", loc)
	}

	if !strings.HasSuffix(loc, filepath.Clean(abs)) {
		return fmt.Errorf("location %s does not have expected suffix %s", loc, filepath.Clean(abs))
	}

	return nil
}

func HasFormatAndDERBase64(comp cdx.Component, formatKey, base64Key string) error {
	format := GetProp(comp, formatKey)
	if format == "" {
		return fmt.Errorf("certificate format property is empty")
	}

	b64 := GetProp(comp, base64Key)
	if b64 == "" {
		return fmt.Errorf("certificate base64 content property is empty")
	}

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("failed to decode base64 content: %w", err)
	}

	_, err = x509.ParseCertificate(raw)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	return nil
}
