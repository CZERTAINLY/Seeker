package x509_test

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/model"
	czX509 "github.com/CZERTAINLY/Seeker/internal/x509"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"
)

func genSelfSignedCert(t *testing.T) (der []byte, cert *x509.Certificate, key *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	templ := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Test Cert"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err = x509.CreateCertificate(rand.Reader, templ, templ, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	return der, cert, key
}

func getProp(comp cdx.Component, name string) string {
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

func requireEvidencePath(t *testing.T, comp cdx.Component) {
	t.Helper()
	require.NotNil(t, comp.Evidence)
	require.NotNil(t, comp.Evidence.Occurrences)
	require.GreaterOrEqual(t, len(*comp.Evidence.Occurrences), 1)
	loc := (*comp.Evidence.Occurrences)[0].Location
	require.NotEmpty(t, loc)
	abs, _ := filepath.Abs("testpath")
	require.True(t, filepath.IsAbs(loc))
	require.True(t, strings.HasSuffix(loc, filepath.Clean(abs)))
}

func requireFormatAndDERBase64(t *testing.T, comp cdx.Component) {
	t.Helper()
	format := getProp(comp, cdxprops.CzertainlyComponentCertificateSourceFormat)
	require.NotEmpty(t, format)

	b64 := getProp(comp, cdxprops.CzertainlyComponentCertificateBase64Content)
	require.NotEmpty(t, b64)
	raw, err := base64.StdEncoding.DecodeString(b64)
	require.NoError(t, err)
	_, err = x509.ParseCertificate(raw)
	require.NoError(t, err)
}

func Test_Detect_PEM_and_DER(t *testing.T) {
	der, _, _ := genSelfSignedCert(t)
	der2, _, _ := genSelfSignedCert(t)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	concatDER := append(append([]byte{}, der...), der2...)

	tests := []struct {
		name      string
		input     []byte
		wantMatch bool
	}{
		{"PEM single", pemBytes, true},
		{"DER single", der, true},
		{"DER concatenated", concatDER, true},
		{"Invalid", []byte("not a cert"), false},
		{"PEM not a cert", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), false},
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

func Test_Detect_ZIP_META_INF(t *testing.T) {
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
