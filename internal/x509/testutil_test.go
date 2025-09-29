package x509_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// genSelfSignedCert generates a self-signed certificate for testing
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

// getProp gets a property value from a CDX component
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

// requireEvidencePath checks that the component has the expected evidence path
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

// requireFormatAndDERBase64 checks that the component has the expected format and base64 content
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
