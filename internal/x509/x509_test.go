package x509_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/model"
	czX509 "github.com/CZERTAINLY/Seeker/internal/x509"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func generateTestCert() ([]byte, *x509.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Test Cert"},
		NotBefore:             time.Now().Add(-time.Minute),
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

	// Encode first as PEM
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
				Bytes: derBytes, // bytes are a cert but type is not; detector should ignore this PEM block
			}),
			wantError: true,
		},
		{
			name:      "multiple DER certificates (concatenated)",
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
				require.ErrorIs(t, err, model.ErrNoMatch)
				return
			}

			require.NoError(t, err)
			require.Len(t, got, 1, "expected one detection record")
			require.GreaterOrEqual(t, len(got[0].Components), 1, "expected at least one component")

			for _, comp := range got[0].Components {
				// 1) Correct component type
				require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)

				// 2) Evidence location present (absolute path filled by detector)
				require.NotNil(t, comp.Evidence, "evidence should be set")
				require.NotNil(t, comp.Evidence.Occurrences, "evidence.occurrences should be set")
				require.GreaterOrEqual(t, len(*comp.Evidence.Occurrences), 1, "at least one occurrence")
				require.NotEmpty(t, (*comp.Evidence.Occurrences)[0].Location, "occurrence location must not be empty")

				// 3) Properties: format + base64 DER
				require.NotNil(t, comp.Properties, "properties should be set")
				props := *comp.Properties

				var formatVal, derB64 string
				for _, p := range props {
					if p.Name == "czertainly:component:certificate:source_format" {
						formatVal = p.Value
					}
					if p.Name == "czertainly:component:certificate:base64_content" {
						derB64 = p.Value
					}
				}
				require.NotEmpty(t, formatVal, "czertainly:component:certificate:source_format should be present")
				require.NotEmpty(t, derB64, "czertainly:component:certificate:base64_content should be present")

				// 4) Base64 decodes and parses as an X.509 cert
				raw, err := base64.StdEncoding.DecodeString(derB64)
				require.NoError(t, err, "base64 decode failed")
				_, err = x509.ParseCertificate(raw)
				require.NoError(t, err, "decoded der-base64 is not a valid certificate")
			}
		})
	}
}
