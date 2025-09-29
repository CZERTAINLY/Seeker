package x509_test

import (
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/model"
	czX509 "github.com/CZERTAINLY/Seeker/internal/x509"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func Test_DER_Detection(t *testing.T) {
	der, _, _ := genSelfSignedCert(t)
	der2, _, _ := genSelfSignedCert(t)
	concatDER := append(append([]byte{}, der...), der2...)

	tests := []struct {
		name      string
		input     []byte
		wantMatch bool
	}{
		{"DER single", der, true},
		{"DER concatenated", concatDER, true},
		{"Invalid", []byte("not a cert"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d czX509.Detector
			got, err := d.Detect(t.Context(), tt.input, "testpath")
			if !tt.wantMatch {
				require.Error(t, err)
				require.ErrorIs(t, err, model.ErrNoMatch)
				return
			}
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.GreaterOrEqual(t, len(got[0].Components), 1)
			for _, comp := range got[0].Components {
				require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
				requireEvidencePath(t, comp)
				requireFormatAndDERBase64(t, comp)
			}
		})
	}
}

func Test_DER_ErrorPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"random bytes", []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{"incomplete DER header", []byte{0x30, 0x82}},
		{"incomplete DER length", []byte{0x30, 0x82, 0x01, 0x00}}, // Valid DER header but incomplete
		{"valid ASN.1 but not certificate", []byte{
			0x30, 0x09, // SEQUENCE
			0x02, 0x01, 0x01, // INTEGER 1
			0x02, 0x01, 0x02, // INTEGER 2
			0x02, 0x01, 0x03, // INTEGER 3
		}},
		{"DER with wrong tag", []byte{
			0x04, 0x10, // OCTET STRING instead of SEQUENCE
			0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x00, 0x00, 0x00, 0x00,
		}},
		{"truncated DER certificate", []byte{
			0x30, 0x82, 0x02, 0x00, // SEQUENCE with length 512 but data is much shorter
			0x30, 0x82, 0x01, 0x00, // Another SEQUENCE but truncated
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

func Test_DER_CertificateChain(t *testing.T) {
	t.Parallel()

	// Create multiple certificates and concatenate them
	certs := make([][]byte, 3)
	for i := range certs {
		der, _, _ := genSelfSignedCert(t)
		certs[i] = der
	}

	// Concatenate all certificates
	var concatenated []byte
	for _, cert := range certs {
		concatenated = append(concatenated, cert...)
	}

	var d czX509.Detector
	got, err := d.Detect(t.Context(), concatenated, "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Len(t, got[0].Components, len(certs))

	// All should be detected as DER format
	for _, comp := range got[0].Components {
		require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
		requireEvidencePath(t, comp)
		requireFormatAndDERBase64(t, comp)
		
		// Check that the source format is set (should be "DER" since we're using raw DER data)
		sourceFormat := getProp(comp, cdxprops.CzertainlyComponentCertificateSourceFormat)
		require.NotEmpty(t, sourceFormat, "source format should be set")
	}
}
