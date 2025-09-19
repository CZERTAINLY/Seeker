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

// A known-good degenerate PKCS#7 (SignedData) PEM block (from the conversation).
// This is just a bundle with one certificate inside.
const pkcs7PEM = `-----BEGIN PKCS7-----
MIIDeAYJKoZIhvcNAQcCoIIDaTCCA2UCAQExADALBgkqhkiG9w0BBwGgggNNMIID
STCCAjGgAwIBAgIUQQLYPi9kDJRpv8OwblURMD2XdRYwDQYJKoZIhvcNAQELBQAw
NDETMBEGA1UEAwwKcGtjczcudGVzdDEQMA4GA1UECgwHVGVzdE9yZzELMAkGA1UE
BhMCVVMwHhcNMjUwOTE5MTAwNTIzWhcNMjYwOTE5MTAwNTIzWjA0MRMwEQYDVQQD
DApwa2NzNy50ZXN0MRAwDgYDVQQKDAdUZXN0T3JnMQswCQYDVQQGEwJVUzCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALNg2NHLR4yziZHRyCHHaJv1xqiU
LEM5UfhqJXyq0hd3Ct6vAW+l0RVC1eRjmPqwRaNCI2d+xsvoI4bxkd/6pMOWnnRS
/vMQxr5Z+etl2IzqE7PDLxE3sATooY3Atz8Goy2kj04EjSEKyUKFKYFMj8u3h5tk
sqyaCZ1+2z97WNWcm9z8V4MQ1veIQqjv0RIg21eNgDozWPxKwOypt/94ZgM6qX45
/aQQonrzDE03mivRcJ1BNCHLepA6k3o3EwJzeCBHb0z1xX5mCjVQw5awERwXQ/bp
tkZrcAldOpdwzFTcIvvEkMvn6r/5tHfxze5cUtZX1g+hz0skNU8bl/wENeUCAwEA
AaNTMFEwHQYDVR0OBBYEFJGGv4k3TfikYmCywloKiDZs+X3eMB8GA1UdIwQYMBaA
FJGGv4k3TfikYmCywloKiDZs+X3eMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN
AQELBQADggEBAGMzeGMvTP+4QfKaiQjkSN/wheM6ij7WPv0Ij3VGZGWB30ZwoDnX
yrWc8dGNsGdqGDP0Nd/XUEWb1ZmCDF3+YgwObRUZF48S5XoFp1ka+UN+L/tPrXRN
4PRVvpEKbc0h27WGbHlP7/shWQwCNs1Zjd/RP3U1OwH0vL2xD87MdOqDAlWgmCms
nHJH2TfbBkIDPI0/uujH6h8bv1tmV9Km6V3UyHI0hHSaHBMjP3xwtqxK+TKKgHpC
8rRaIF49k+f2e0zy94SGVrUY6llZTN4C1JfrIiD0EjS4gEjKepYfVSrpMb3N1zgH
9yfg4Q+0kgHEID7nkawBT9vvO36uP8dSC9AxAA==
-----END PKCS7-----`

// A CMS header variant: same base64 body, but BEGIN/END CMS.
// Detector accepts "CMS" in the PEM loop.
const cmsPEM = `-----BEGIN CMS-----
MIIDeAYJKoZIhvcNAQcCoIIDaTCCA2UCAQExADALBgkqhkiG9w0BBwGgggNNMIID
STCCAjGgAwIBAgIUQQLYPi9kDJRpv8OwblURMD2XdRYwDQYJKoZIhvcNAQELBQAw
NDETMBEGA1UEAwwKcGtjczcudGVzdDEQMA4GA1UECgwHVGVzdE9yZzELMAkGA1UE
BhMCVVMwHhcNMjUwOTE5MTAwNTIzWhcNMjYwOTE5MTAwNTIzWjA0MRMwEQYDVQQD
DApwa2NzNy50ZXN0MRAwDgYDVQQKDAdUZXN0T3JnMQswCQYDVQQGEwJVUzCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALNg2NHLR4yziZHRyCHHaJv1xqiU
LEM5UfhqJXyq0hd3Ct6vAW+l0RVC1eRjmPqwRaNCI2d+xsvoI4bxkd/6pMOWnnRS
/vMQxr5Z+etl2IzqE7PDLxE3sATooY3Atz8Goy2kj04EjSEKyUKFKYFMj8u3h5tk
sqyaCZ1+2z97WNWcm9z8V4MQ1veIQqjv0RIg21eNgDozWPxKwOypt/94ZgM6qX45
/aQQonrzDE03mivRcJ1BNCHLepA6k3o3EwJzeCBHb0z1xX5mCjVQw5awERwXQ/bp
tkZrcAldOpdwzFTcIvvEkMvn6r/5tHfxze5cUtZX1g+hz0skNU8bl/wENeUCAwEA
AaNTMFEwHQYDVR0OBBYEFJGGv4k3TfikYmCywloKiDZs+X3eMB8GA1UdIwQYMBaA
FJGGv4k3TfikYmCywloKiDZs+X3eMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN
AQELBQADggEBAGMzeGMvTP+4QfKaiQjkSN/wheM6ij7WPv0Ij3VGZGWB30ZwoDnX
yrWc8dGNsGdqGDP0Nd/XUEWb1ZmCDF3+YgwObRUZF48S5XoFp1ka+UN+L/tPrXRN
4PRVvpEKbc0h27WGbHlP7/shWQwCNs1Zjd/RP3U1OwH0vL2xD87MdOqDAlWgmCms
nHJH2TfbBkIDPI0/uujH6h8bv1tmV9Km6V3UyHI0hHSaHBMjP3xwtqxK+TKKgHpC
8rRaIF49k+f2e0zy94SGVrUY6llZTN4C1JfrIiD0EjS4gEjKepYfVSrpMb3N1zgH
9yfg4Q+0kgHEID7nkawBT9vvO36uP8dSC9AxAA==
-----END CMS-----`

func Test_Detect_PKCS7_PEM_and_CMS_PEM(t *testing.T) {
	t.Parallel()
	var d czX509.Detector

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"PKCS7 PEM", []byte(pkcs7PEM)},
		{"CMS PEM", []byte(cmsPEM)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := d.Detect(t.Context(), tc.in, "testpath")
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.GreaterOrEqual(t, len(got[0].Components), 1)
			seen := false
			for _, comp := range got[0].Components {
				require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
				requireEvidencePath(t, comp)
				requireFormatAndDERBase64(t, comp)
				if getProp(comp, cdxprops.CzertainlyComponentCertificateSourceFormat) == "PKCS7-PEM" {
					seen = true
				}
			}
			require.True(t, seen, "expected a component with format PKCS7-PEM")
		})
	}
}

func Test_Detect_PKCS7_DER(t *testing.T) {
	t.Parallel()
	// Extract DER bytes by stripping the PEM armor and base64-decoding.
	var b64 string
	for _, line := range strings.Split(pkcs7PEM, "\n") {
		if strings.HasPrefix(line, "-----") {
			continue
		}
		b64 += strings.TrimSpace(line)
	}
	der, err := base64.StdEncoding.DecodeString(b64)
	require.NoError(t, err)
	require.NotEmpty(t, der)

	var d czX509.Detector
	got, err := d.Detect(t.Context(), der, "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.GreaterOrEqual(t, len(got[0].Components), 1)

	found := false
	for _, comp := range got[0].Components {
		require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
		requireEvidencePath(t, comp)
		requireFormatAndDERBase64(t, comp)
		if getProp(comp, cdxprops.CzertainlyComponentCertificateSourceFormat) == "PKCS7-DER" {
			found = true
		}
	}
	require.True(t, found, "expected a component with format PKCS7-DER")
}

func Test_Detect_ZIP_META_INF_Variants(t *testing.T) {
	t.Parallel()

	// Reuse a normal DER cert for the PEM-in-RSA entry (as in your original test)
	derCert, _, _ := genSelfSignedCert(t)
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})

	// DER PKCS#7 bytes for the .PK7 entry (from pkcs7PEM)
	var b64 string
	for _, line := range strings.Split(pkcs7PEM, "\n") {
		if strings.HasPrefix(line, "-----") {
			continue
		}
		b64 += strings.TrimSpace(line)
	}
	p7der, err := base64.StdEncoding.DecodeString(b64)
	require.NoError(t, err)

	// Build a ZIP with both META-INF/CERT.RSA (PEM cert) and META-INF/FOO.PK7 (PKCS7 DER)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	w1, err := zw.Create("META-INF/CERT.RSA")
	require.NoError(t, err)
	_, err = w1.Write(pemCert)
	require.NoError(t, err)

	w2, err := zw.Create("META-INF/FOO.PK7")
	require.NoError(t, err)
	_, err = w2.Write(p7der)
	require.NoError(t, err)

	require.NoError(t, zw.Close())

	var d czX509.Detector
	got, err := d.Detect(t.Context(), buf.Bytes(), "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.GreaterOrEqual(t, len(got[0].Components), 2) // one from CERT.RSA, one from PK7

	foundZip := 0
	for _, comp := range got[0].Components {
		require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
		requireEvidencePath(t, comp)
		requireFormatAndDERBase64(t, comp)
		if strings.HasPrefix(getProp(comp, cdxprops.CzertainlyComponentCertificateSourceFormat), "ZIP/") {
			foundZip++
		}
	}
	require.GreaterOrEqual(t, foundZip, 2, "expected at least two ZIP/* components from different META-INF entries")
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
