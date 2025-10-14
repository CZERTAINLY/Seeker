package x509_test

import (
	"bytes"
	"crypto/x509"
	"testing"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	czX509 "github.com/CZERTAINLY/Seeker/internal/x509"
	cdx "github.com/CycloneDX/cyclonedx-go"
	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/stretchr/testify/require"
)

func Test_Detect_JKS_Truststore(t *testing.T) {
	der, _, _ := genSelfSignedCert(t)

	// Create a JKS with a single trusted cert entry
	ks := keystore.New()
	err := ks.SetTrustedCertificateEntry("alias1", keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate: keystore.Certificate{
			Type:    "X509",
			Content: der,
		},
	})
	require.NoError(t, err)

	var buf bytes.Buffer
	err = ks.Store(&buf, []byte("changeit"))
	require.NoError(t, err)
	jksBytes := buf.Bytes()

	var d czX509.Detector
	got, err := d.Detect(t.Context(), jksBytes, "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.GreaterOrEqual(t, len(got[0].Components), 1)

	foundJKS := false
	for _, comp := range got[0].Components {
		require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
		requireEvidencePath(t, comp)
		requireFormatAndDERBase64(t, comp)

		format := getProp(comp, cdxprops.CzertainlyComponentCertificateSourceFormat)
		if format == "JKS" || format == "JCEKS" {
			foundJKS = true
		}
	}
	require.True(t, foundJKS, "expected a component with format JKS/JCEKS")
}

func Test_Detect_JKS_PrivateKeyEntry_WithChain(t *testing.T) {
	t.Parallel()
	// Leaf + "CA" (both self-signed for simplicity, but store a chain of two)
	leafDER, leafCert, leafKey := genSelfSignedCert(t)
	caDER, _, _ := genSelfSignedCert(t)

	// JKS with a PrivateKeyEntry that contains a chain [leaf, ca]
	ks := keystore.New()
	// encode leaf key in PKCS#8 for keystore-go
	p8, err := x509.MarshalPKCS8PrivateKey(leafKey)
	require.NoError(t, err)

	entry := keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   p8,
		CertificateChain: []keystore.Certificate{
			{Type: "X509", Content: leafDER},
			{Type: "X509", Content: caDER},
		},
	}
	require.NoError(t, ks.SetPrivateKeyEntry("leaf", entry, []byte("changeit")))

	var buf bytes.Buffer
	require.NoError(t, ks.Store(&buf, []byte("changeit")))

	var d czX509.Detector
	got, err := d.Detect(t.Context(), buf.Bytes(), "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.GreaterOrEqual(t, len(got[0].Components), 2) // leaf + ca

	foundJKS := false
	for _, comp := range got[0].Components {
		require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
		requireEvidencePath(t, comp)
		requireFormatAndDERBase64(t, comp)
		if format := getProp(comp, cdxprops.CzertainlyComponentCertificateSourceFormat); format == "JKS" {
			foundJKS = true
		}
	}
	require.True(t, foundJKS, "expected a JKS component from PrivateKeyEntry chain")
	_ = leafCert // silence if unused in assertions
}

func Test_JKS_Edge_Cases(t *testing.T) {
	t.Parallel()

	// Test JKS with malformed data to improve sniff coverage
	badJKSData := []byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x99} // Bad version

	var d czX509.Detector
	_, err := d.Detect(t.Context(), badJKSData, "testpath")
	require.NoError(t, err)

	// Test with data that looks like magic but isn't long enough
	shortData := []byte{0xFE, 0xED} // Too short
	_, err = d.Detect(t.Context(), shortData, "testpath")
	require.NoError(t, err)
}
