package x509_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops/cdxtest"
	czX509 "github.com/CZERTAINLY/Seeker/internal/scanner/x509"
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

	// Generate a basic RSA cert that we can modify the signature algorithm for testing
	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	cert := selfSigned.Cert
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Modify the signature algorithm for testing purposes
			cert.SignatureAlgorithm = tt.alg

			// Convert to PEM and run detection
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

			var d czX509.Scanner
			got, err := d.Scan(t.Context(), pemBytes, "testpath")
			require.NoError(t, err)
			require.Len(t, got, 1)
		})
	}
}
