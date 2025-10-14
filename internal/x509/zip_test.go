package x509_test

import (
	"archive/zip"
	"bytes"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	czX509 "github.com/CZERTAINLY/Seeker/internal/x509"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func Test_ZIP_META_INF_Detection(t *testing.T) {
	der, _, _ := genSelfSignedCert(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// Build a ZIP with META-INF/CERT.RSA containing the PEM cert
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("META-INF/CERT.RSA")
	require.NoError(t, err)
	_, err = w.Write(pemBytes)
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	var d czX509.Detector
	got, err := d.Detect(t.Context(), buf.Bytes(), "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.GreaterOrEqual(t, len(got[0].Components), 1)

	foundZip := false
	for _, comp := range got[0].Components {
		require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
		requireEvidencePath(t, comp)
		requireFormatAndDERBase64(t, comp)
		if strings.HasPrefix(getProp(comp, cdxprops.CzertainlyComponentCertificateSourceFormat), "ZIP/") {
			foundZip = true
		}
	}
	require.True(t, foundZip, "expected a component with format ZIP/*")
}

func Test_ZIP_ErrorPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{"corrupted ZIP", []byte("PK\x03\x04corrupted")},
		{"empty ZIP-like", []byte("PK\x03\x04")},
		{"ZIP with invalid central directory", []byte{
			'P', 'K', 0x03, 0x04, // Local file header signature
			0x14, 0x00, // Version needed to extract
			0x00, 0x00, // General purpose bit flag
			0x00, 0x00, // Compression method
			0x00, 0x00, // File last modification time
			0x00, 0x00, // File last modification date
			0x00, 0x00, 0x00, 0x00, // CRC-32
			0x00, 0x00, 0x00, 0x00, // Compressed size
			0x00, 0x00, 0x00, 0x00, // Uncompressed size
			0x04, 0x00, // File name length
			0x00, 0x00, // Extra field length
			't', 'e', 's', 't', // File name
			// No actual file data or central directory
		}},
	}

	var d czX509.Detector
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := d.Detect(t.Context(), tt.data, "testpath")
			require.NoError(t, err)
		})
	}
}

func Test_ZIP_ValidButNoCerts(t *testing.T) {
	t.Parallel()

	// Create a valid ZIP with no certificate files
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// Add a regular file that's not a certificate
	w, err := zw.Create("README.txt")
	require.NoError(t, err)
	_, err = w.Write([]byte("This is just a text file"))
	require.NoError(t, err)

	// Add a file in META-INF but not a cert
	w, err = zw.Create("META-INF/MANIFEST.MF")
	require.NoError(t, err)
	_, err = w.Write([]byte("Manifest-Version: 1.0\n"))
	require.NoError(t, err)

	require.NoError(t, zw.Close())

	var d czX509.Detector
	_, err = d.Detect(t.Context(), buf.Bytes(), "testpath")
	require.NoError(t, err)
}

func Test_ZIP_InvalidCertInMetaINF(t *testing.T) {
	t.Parallel()

	// Create a ZIP with files that look like certs but aren't
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// Add invalid certificate data in META-INF
	w, err := zw.Create("META-INF/CERT.RSA")
	require.NoError(t, err)
	_, err = w.Write([]byte("not a certificate"))
	require.NoError(t, err)

	w, err = zw.Create("META-INF/CERT.DSA")
	require.NoError(t, err)
	_, err = w.Write([]byte("also not a certificate"))
	require.NoError(t, err)

	w, err = zw.Create("META-INF/TEST.PK7")
	require.NoError(t, err)
	_, err = w.Write([]byte("fake pkcs7 data"))
	require.NoError(t, err)

	require.NoError(t, zw.Close())

	var d czX509.Detector
	_, err = d.Detect(t.Context(), buf.Bytes(), "testpath")
	require.NoError(t, err)
}

func Test_ZIP_MultipleFiles(t *testing.T) {
	t.Parallel()

	der, _, _ := genSelfSignedCert(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// Create a ZIP with multiple certificate files
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// Add certificate files with different extensions
	extensions := []string{"CERT.RSA", "CERT.DSA", "CERT.EC", "TEST.PK7"}
	for _, ext := range extensions {
		w, err := zw.Create("META-INF/" + ext)
		require.NoError(t, err)
		_, err = w.Write(pemBytes)
		require.NoError(t, err)
	}

	// Add some non-certificate files too
	w, err := zw.Create("META-INF/MANIFEST.MF")
	require.NoError(t, err)
	_, err = w.Write([]byte("Manifest-Version: 1.0\n"))
	require.NoError(t, err)

	w, err = zw.Create("some/other/file.txt")
	require.NoError(t, err)
	_, err = w.Write([]byte("regular file"))
	require.NoError(t, err)

	require.NoError(t, zw.Close())

	var d czX509.Detector
	got, err := d.Detect(t.Context(), buf.Bytes(), "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)

	// We should find at least one certificate from the ZIP files
	// Note: Some files might be detected multiple times (as PEM and as ZIP),
	// so we just check that we have some components
	require.GreaterOrEqual(t, len(got[0].Components), 1)

	// Check that at least some certificates were found with ZIP source
	zipCount := 0
	for _, comp := range got[0].Components {
		require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
		requireEvidencePath(t, comp)
		requireFormatAndDERBase64(t, comp)
		if strings.HasPrefix(getProp(comp, cdxprops.CzertainlyComponentCertificateSourceFormat), "ZIP/") {
			zipCount++
		}
	}
	require.GreaterOrEqual(t, zipCount, 1, "expected at least one certificate to be detected as ZIP source")
}
