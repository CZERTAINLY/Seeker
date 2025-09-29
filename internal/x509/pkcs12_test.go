package x509_test

import (
	"crypto/rand"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/model"
	czX509 "github.com/CZERTAINLY/Seeker/internal/x509"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

//nolint:staticcheck
func Test_Detect_PKCS12_WithKey(t *testing.T) {
	_, cert, key := genSelfSignedCert(t)

	// Build a PFX with key+cert
	pfx, err := pkcs12.Encode(rand.Reader, key, cert, nil, "changeit")
	require.NoError(t, err)

	var d czX509.Detector
	got, err := d.Detect(t.Context(), pfx, "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.GreaterOrEqual(t, len(got[0].Components), 1)

	// At least one component should be tagged PKCS12
	foundPKCS12 := false
	for _, comp := range got[0].Components {
		require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
		requireEvidencePath(t, comp)
		requireFormatAndDERBase64(t, comp)
		if getProp(comp, cdxprops.CzertainlyComponentCertificateSourceFormat) == "PKCS12" {
			foundPKCS12 = true
		}
	}
	require.True(t, foundPKCS12, "expected a component with format PKCS12")
}

func Test_PKCS12_Edge_Cases(t *testing.T) {
	t.Parallel()
	
	// Test PKCS12 with different passwords and edge cases
	_, cert, key := genSelfSignedCert(t)
	
	// Test with empty password
	pfx, err := pkcs12.Encode(rand.Reader, key, cert, nil, "")
	require.NoError(t, err)
	
	var d czX509.Detector
	got, err := d.Detect(t.Context(), pfx, "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.GreaterOrEqual(t, len(got[0].Components), 1)
	
	// Verify PKCS12 format is detected
	found := false
	for _, comp := range got[0].Components {
		if getProp(comp, cdxprops.CzertainlyComponentCertificateSourceFormat) == "PKCS12" {
			found = true
			break
		}
	}
	require.True(t, found, "expected a component with format PKCS12")
}

func Test_PKCS12_InvalidData(t *testing.T) {
	t.Parallel()
	
	// Test PKCS12 sniffing with various invalid data
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x30, 0x82}},
		{"invalid ASN.1", []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{"wrong tag", []byte{0x31, 0x82, 0x01, 0x23}}, // SET instead of SEQUENCE
		{"wrong version", []byte{
			0x30, 0x82, 0x01, 0x23, // SEQUENCE
			0x02, 0x01, 0xFF, // version 255 (too high)
		}},
	}
	
	var d czX509.Detector
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := d.Detect(t.Context(), tt.data, "testpath")
			require.Error(t, err)
			require.ErrorIs(t, err, model.ErrNoMatch)
		})
	}
}