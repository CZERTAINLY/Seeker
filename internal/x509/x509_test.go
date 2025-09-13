package x509_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/model"
	czX509 "github.com/CZERTAINLY/Seeker/internal/x509"
	"github.com/stretchr/testify/require"
)

func generateTestCert() ([]byte, *x509.Certificate, error) {
	// Create a simple self-signed certificate for testing
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Cert"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return derBytes, cert, nil
}

func TestIsX509(t *testing.T) {
	derBytes, _, err := generateTestCert()
	require.NoError(t, err)
	derBytes2, _, err := generateTestCert()
	require.NoError(t, err)

	// Encode as PEM
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	tests := []struct {
		name      string
		input     []byte
		wantError bool
	}{
		{
			name:      "valid PEM cert",
			input:     pemBytes,
			wantError: false,
		},
		{
			name:      "valid DER cert",
			input:     derBytes,
			wantError: false,
		},
		{
			name:      "invalid input",
			input:     []byte("not a cert"),
			wantError: true,
		},
		{
			name: "PEM block not a certificate",
			input: pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: derBytes,
			}),
			wantError: true,
		},
		{
			name:      "multiple DER certificates",
			input:     append(derBytes, derBytes2...),
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d czX509.Detector
			got, err := d.Detect(tt.input, "testpath")
			if tt.wantError {
				require.Error(t, err)
				require.ErrorIs(t, model.ErrNoMatch, err)
			} else {
				require.NoError(t, err)
				require.Len(t, got, 1)
				require.Equal(t, "X509", got[0].Typ)
			}
		})
	}
}
