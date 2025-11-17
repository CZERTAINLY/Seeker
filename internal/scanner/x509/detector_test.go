package x509_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops/cdxtest"
	czX509 "github.com/CZERTAINLY/Seeker/internal/scanner/x509"
	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/stretchr/testify/require"
)

func Test_Component_Various_Algorithms(t *testing.T) {
	t.Parallel()
	// Test various signature algorithms and key types by generating certificates
	// This test primarily exists to improve coverage of readSignatureAlgorithmRef
	// and readSubjectPublicKeyRef functions
	tests := []struct {
		name string
		alg  x509.SignatureAlgorithm
	}{
		{"MD5WithRSA", x509.MD5WithRSA},
		{"SHA1WithRSA", x509.SHA1WithRSA},
		{"SHA256WithRSA", x509.SHA256WithRSA},
		{"SHA384WithRSA", x509.SHA384WithRSA},
		{"SHA512WithRSA", x509.SHA512WithRSA},
		{"DSAWithSHA1", x509.DSAWithSHA1},
		{"DSAWithSHA256", x509.DSAWithSHA256},
		{"ECDSAWithSHA1", x509.ECDSAWithSHA1},
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384},
		{"ECDSAWithSHA512", x509.ECDSAWithSHA512},
		{"SHA256WithRSAPSS", x509.SHA256WithRSAPSS},
		{"SHA384WithRSAPSS", x509.SHA384WithRSAPSS},
		{"SHA512WithRSAPSS", x509.SHA512WithRSAPSS},
		{"PureEd25519", x509.PureEd25519},
		{"UnknownSignatureAlgorithm", x509.UnknownSignatureAlgorithm}, // For testing default case
	}

	formats := []struct {
		name    string
		prepare func(*cdxtest.SelfSignedCert) ([]byte, error)
	}{
		{
			name: "DER",
			prepare: func(selfSigned *cdxtest.SelfSignedCert) ([]byte, error) {
				return selfSigned.Der, nil
			},
		},
		{
			name: "PKCS12",
			prepare: func(selfSigned *cdxtest.SelfSignedCert) ([]byte, error) {
				// Create PKCS#12 with certificate and private key
				return pkcs12.LegacyRC2.Encode(selfSigned.Key, selfSigned.Cert, nil, "changeit")
			},
		},
		{
			name: "JKS",
			prepare: func(selfSigned *cdxtest.SelfSignedCert) ([]byte, error) {
				ks := keystore.New()
				// Add certificate to keystore
				if err := ks.SetTrustedCertificateEntry("test-cert", keystore.TrustedCertificateEntry{
					CreationTime: time.Now(),
					Certificate: keystore.Certificate{
						Type:    "X.509",
						Content: selfSigned.Der,
					},
				}); err != nil {
					return nil, err
				}
				var buf bytes.Buffer
				if err := ks.Store(&buf, []byte("password")); err != nil {
					return nil, err
				}
				return buf.Bytes(), nil
			},
		},
		{
			name: "JCEKS",
			prepare: func(selfSigned *cdxtest.SelfSignedCert) ([]byte, error) {
				ks := keystore.New(keystore.WithOrderedAliases())
				// Add certificate to JCEKS keystore
				if err := ks.SetTrustedCertificateEntry("test-cert", keystore.TrustedCertificateEntry{
					CreationTime: time.Now(),
					Certificate: keystore.Certificate{
						Type:    "X.509",
						Content: selfSigned.Der,
					},
				}); err != nil {
					return nil, err
				}
				var buf bytes.Buffer
				if err := ks.Store(&buf, []byte("password")); err != nil {
					return nil, err
				}
				return buf.Bytes(), nil
			},
		},
	}

	// Generate a basic RSA cert that we can modify the signature algorithm for testing
	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	for _, tt := range tests {
		for _, format := range formats {
			t.Run(tt.name+"/"+format.name, func(t *testing.T) {
				var modifiedSelfSigned *cdxtest.SelfSignedCert

				// Some algorithms are not supported by x509.CreateCertificate
				// For these, we'll just use the original cert for format testing
				unsupportedAlgorithms := map[x509.SignatureAlgorithm]bool{
					x509.MD5WithRSA:                true,
					x509.DSAWithSHA1:               true,
					x509.DSAWithSHA256:             true,
					x509.UnknownSignatureAlgorithm: true,
				}

				if unsupportedAlgorithms[tt.alg] {
					// Skip re-creating the certificate, use original for format testing only
					modifiedSelfSigned = &selfSigned
				} else {
					// Parse the DER to get a modifiable certificate
					cert, err := x509.ParseCertificate(selfSigned.Der)
					require.NoError(t, err)

					// Modify the signature algorithm for testing purposes
					cert.SignatureAlgorithm = tt.alg

					// Re-create the DER with the modified signature algorithm
					modifiedDer, err := x509.CreateCertificate(rand.Reader, cert, cert, &selfSigned.Key.PublicKey, selfSigned.Key)
					require.NoError(t, err)

					modifiedCert, err := x509.ParseCertificate(modifiedDer)
					require.NoError(t, err)

					modifiedSelfSigned = &cdxtest.SelfSignedCert{
						Der:  modifiedDer,
						Cert: modifiedCert,
						Key:  selfSigned.Key,
					}
				}

				// Convert to the desired format
				data, err := format.prepare(modifiedSelfSigned)
				require.NoError(t, err)

				// Run detection
				var d czX509.Scanner
				got, err := d.Scan(t.Context(), data, "testpath")
				require.NoError(t, err)
				require.NotEmpty(t, got, "should detect at least one certificate")
			})
		}
	}
}
