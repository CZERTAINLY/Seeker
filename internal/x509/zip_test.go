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