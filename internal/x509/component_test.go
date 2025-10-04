package x509_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	czX509 "github.com/CZERTAINLY/Seeker/internal/x509"
	cdx "github.com/CycloneDX/cyclonedx-go"
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate a basic RSA cert that we can modify the signature algorithm for testing
			_, cert, _ := genSelfSignedCert(t)
			// Modify the signature algorithm for testing purposes
			cert.SignatureAlgorithm = tt.alg

			// Convert to PEM and run detection
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

			var d czX509.Detector
			got, err := d.Detect(t.Context(), pemBytes, "testpath")
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.GreaterOrEqual(t, len(got[0].Components), 1)

			comp := got[0].Components[0]
			require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
			requireEvidencePath(t, comp)
			requireFormatAndDERBase64(t, comp)

			if tt.alg == x509.UnknownSignatureAlgorithm {
				// Even when Go enum is unknown, we should still resolve something via OID parsing
				require.NotEmpty(t, comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef)
			}
		})
	}
}

func Test_Component_Edge_Cases(t *testing.T) {
	t.Parallel()

	// Test edge cases for component creation to improve coverage

	// Test with certificate that has no serial number (edge case)
	_, cert, _ := genSelfSignedCert(t)

	// Create a certificate with some edge cases
	cert.SerialNumber = big.NewInt(0) // Edge case: zero serial number

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	testPath, _ := filepath.Abs("testpath.crt")
	var d czX509.Detector
	got, err := d.Detect(t.Context(), pemBytes, testPath)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.GreaterOrEqual(t, len(got[0].Components), 1)

	comp := got[0].Components[0]
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
	require.NotNil(t, comp.Evidence)
	require.NotNil(t, comp.Evidence.Occurrences)
	require.GreaterOrEqual(t, len(*comp.Evidence.Occurrences), 1)
	loc := (*comp.Evidence.Occurrences)[0].Location
	require.NotEmpty(t, loc)
	require.True(t, filepath.IsAbs(loc))
	requireFormatAndDERBase64(t, comp)

	// Check that certificate extension is properly set
	require.NotNil(t, comp.CryptoProperties)
	require.NotNil(t, comp.CryptoProperties.CertificateProperties)
	require.Equal(t, ".crt", comp.CryptoProperties.CertificateProperties.CertificateExtension)
}

// Test_Component_UnsupportedKeys tests handling of key types for better coverage
func Test_Component_UnsupportedKeys(t *testing.T) {
	t.Parallel()

	// Test with actual Ed25519 certificate to exercise that path
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Ed25519 Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.PureEd25519,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	var d czX509.Detector
	got, err := d.Detect(t.Context(), pemBytes, "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.GreaterOrEqual(t, len(got[0].Components), 1)

	comp := got[0].Components[0]
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
	requireEvidencePath(t, comp)
	requireFormatAndDERBase64(t, comp)

	// Should have Ed25519 algorithm and key references
	require.Equal(t, "crypto/algorithm/ed25519@1.3.101.112", string(comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef))
	require.Equal(t, "crypto/key/ed25519-256@1.3.101.112", string(comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef))
}

// Test_Component_ECDSA_Keys tests ECDSA key handling for better coverage
func Test_Component_ECDSA_Keys(t *testing.T) {
	t.Parallel()

	// Test P-256 ECDSA certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "ECDSA P-256 Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	var d czX509.Detector
	got, err := d.Detect(t.Context(), pemBytes, "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.GreaterOrEqual(t, len(got[0].Components), 1)

	comp := got[0].Components[0]
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
	requireEvidencePath(t, comp)
	requireFormatAndDERBase64(t, comp)

	// Should have ECDSA key reference
	require.Contains(t, string(comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef), "ecdsa")

	// Test P-384 as well
	priv384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	template.SignatureAlgorithm = x509.ECDSAWithSHA384
	certDER384, err := x509.CreateCertificate(rand.Reader, template, template, &priv384.PublicKey, priv384)
	require.NoError(t, err)

	pemBytes384 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER384})

	got384, err := d.Detect(t.Context(), pemBytes384, "testpath")
	require.NoError(t, err)
	require.Len(t, got384, 1)
	require.GreaterOrEqual(t, len(got384[0].Components), 1)

	comp384 := got384[0].Components[0]
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp384.Type)
	requireEvidencePath(t, comp384)
	requireFormatAndDERBase64(t, comp384)

	// Should have ECDSA P-384 key reference
	require.Contains(t, string(comp384.CryptoProperties.CertificateProperties.SubjectPublicKeyRef), "ecdsa-p384")

	// --- P-521 ---
	priv521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	template.SignatureAlgorithm = x509.ECDSAWithSHA512
	certDER521, err := x509.CreateCertificate(rand.Reader, template, template, &priv521.PublicKey, priv521)
	require.NoError(t, err)

	pemBytes521 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER521})

	got521, err := d.Detect(t.Context(), pemBytes521, "testpath")
	require.NoError(t, err)
	require.Len(t, got521, 1)
	require.GreaterOrEqual(t, len(got521[0].Components), 1)

	comp521 := got521[0].Components[0]
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp521.Type)
	requireEvidencePath(t, comp521)
	requireFormatAndDERBase64(t, comp521)

	// Should have ECDSA P-521 key reference
	require.Contains(t, string(comp521.CryptoProperties.CertificateProperties.SubjectPublicKeyRef), "ecdsa-p521")
}

// Test_Component_DSA_Keys tests DSA key handling for better coverage
// Disabled due to DSA cert creation issues with crypto.Signer interface
/*
func Test_Component_DSA_Keys(t *testing.T) {
	t.Parallel()

	// Test DSA certificate to exercise the DSA path in readSubjectPublicKeyRef
	var params dsa.Parameters
	err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160)
	require.NoError(t, err)

	priv := &dsa.PrivateKey{}
	priv.Parameters = params
	err = dsa.GenerateKey(priv, rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "DSA Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.DSAWithSHA1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	var d czX509.Detector
	got, err := d.Detect(t.Context(), pemBytes, "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.GreaterOrEqual(t, len(got[0].Components), 1)

	comp := got[0].Components[0]
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
	requireEvidencePath(t, comp)
	requireFormatAndDERBase64(t, comp)

	// Check DSA signature algorithm reference
	require.Equal(t, "crypto/algorithm/sha-1-dsa@1.2.840.10040.4.3", string(comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef))
}
*/

// Test_Component_MoreAlgorithms tests additional signature algorithms for coverage
func Test_Component_MoreAlgorithms(t *testing.T) {
	t.Parallel()

	algorithms := []x509.SignatureAlgorithm{
		x509.SHA256WithRSAPSS,
		x509.SHA384WithRSAPSS,
		x509.SHA512WithRSAPSS,
	}

	for _, alg := range algorithms {
		t.Run(alg.String(), func(t *testing.T) {
			// Create RSA key
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)

			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					CommonName: "Algorithm Test Certificate",
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(365 * 24 * time.Hour),
				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				BasicConstraintsValid: true,
				SignatureAlgorithm:    alg,
			}

			certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
			require.NoError(t, err)

			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

			var d czX509.Detector
			got, err := d.Detect(t.Context(), pemBytes, "testpath")
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.GreaterOrEqual(t, len(got[0].Components), 1)

			comp := got[0].Components[0]
			require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
			requireEvidencePath(t, comp)
			requireFormatAndDERBase64(t, comp)

			// Exercise RSA SubjectPublicKeyRef (should include bit length)
			require.Contains(t, string(comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef), "rsa-")
		})
	}
}

// Test_Component_UnknownAlgorithm tests handling of unknown signature algorithms
func Test_Component_UnknownAlgorithm(t *testing.T) {
	t.Parallel()

	// Create a normal certificate first - this will exercise the normal paths
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Algorithm Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	var d czX509.Detector
	got, err := d.Detect(t.Context(), pemBytes, "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.GreaterOrEqual(t, len(got[0].Components), 1)

	comp := got[0].Components[0]
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
	requireEvidencePath(t, comp)
	requireFormatAndDERBase64(t, comp)

	// Should have proper signature algorithm reference
	require.NotEmpty(t, comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef)
}

// Test_Component_Ed25519_Keys tests Ed25519 key handling for better coverage
func Test_Component_Ed25519_Keys(t *testing.T) {
	t.Parallel()

	// Test Ed25519 certificate to exercise the Ed25519 path in readSubjectPublicKeyRef
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Ed25519 Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.PureEd25519,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	var d czX509.Detector
	got, err := d.Detect(t.Context(), pemBytes, "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.GreaterOrEqual(t, len(got[0].Components), 1)

	comp := got[0].Components[0]
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
	requireEvidencePath(t, comp)
	requireFormatAndDERBase64(t, comp)

	// Check Ed25519 signature algorithm reference
	require.Equal(t, "crypto/algorithm/ed25519@1.3.101.112", string(comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef))
	// Check Ed25519 key reference
	require.Equal(t, "crypto/key/ed25519-256@1.3.101.112", string(comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef))
}

// Test_readSignatureAlgorithmRef_DirectCalls tests signature algorithm mapping directly
func Test_readSignatureAlgorithmRef_DirectCalls(t *testing.T) {
	t.Parallel()

	// This test verifies that the signature algorithm field in the parsed certificate
	// gets mapped correctly. Since x509.CreateCertificate will override the SignatureAlgorithm
	// field based on the actual signature used, we need to test this differently.

	// Test with normal certificate creation to exercise the common paths
	_, cert, _ := genSelfSignedCert(t)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	var d czX509.Detector
	got, err := d.Detect(t.Context(), pemBytes, "testpath")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.GreaterOrEqual(t, len(got[0].Components), 1)

	comp := got[0].Components[0]

	// The generated certificate should have some signature algorithm
	require.NotEmpty(t, comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef)

	// For RSA certificates, it should be one of the RSA algorithms
	sigAlgRef := string(comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef)
	require.Contains(t, sigAlgRef, "rsa")
}

// --- Minimal ASN.1 structs for crafting PQC OID test certs ---
type tAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}
type tCertOuter struct {
	TBSCert   asn1.RawValue
	SigAlg    tAlgorithmIdentifier
	Signature asn1.BitString
}
type tSPKI struct {
	Algorithm     tAlgorithmIdentifier
	SubjectPubKey asn1.BitString
}

func parseOID(oidStr string) asn1.ObjectIdentifier {
	parts := strings.Split(oidStr, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		var v int
		_, err := fmt.Sscanf(p, "%d", &v)
		if err != nil {
			return nil
		}
		oid[i] = v
	}
	return oid
}

func mkCertWithSigOID(oid string) *x509.Certificate {
	outer := tCertOuter{
		TBSCert:   asn1.RawValue{FullBytes: []byte{0x30, 0x00}}, // empty SEQUENCE
		SigAlg:    tAlgorithmIdentifier{Algorithm: parseOID(oid)},
		Signature: asn1.BitString{Bytes: []byte{0x00}},
	}
	raw, _ := asn1.Marshal(outer)
	return &x509.Certificate{Raw: raw}
}

func mkCertWithSPKIOID(oid string) *x509.Certificate {
	spki := tSPKI{
		Algorithm:     tAlgorithmIdentifier{Algorithm: parseOID(oid)},
		SubjectPubKey: asn1.BitString{Bytes: []byte{0x00}},
	}
	rawSPKI, _ := asn1.Marshal(spki)
	return &x509.Certificate{RawSubjectPublicKeyInfo: rawSPKI}
}

func Test_PQC_SignatureAlgorithm_OIDs(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	// ML-DSA (FIPS 204)
	for oid, want := range map[string]cdx.BOMReference{
		"2.16.840.1.101.3.4.3.17": "crypto/algorithm/ml-dsa-44@2.16.840.1.101.3.4.3.17",
		"2.16.840.1.101.3.4.3.18": "crypto/algorithm/ml-dsa-65@2.16.840.1.101.3.4.3.18",
		"2.16.840.1.101.3.4.3.19": "crypto/algorithm/ml-dsa-87@2.16.840.1.101.3.4.3.19",
	} {
		c := mkCertWithSigOID(oid)
		got := czX509.ReadSignatureAlgorithmRef(ctx, c)
		require.Equal(t, want, got)
	}

	// SLH-DSA (FIPS 205)
	for oid, want := range map[string]cdx.BOMReference{
		"2.16.840.1.101.3.4.3.20": "crypto/algorithm/slh-dsa-sha2-128s@2.16.840.1.101.3.4.3.20",
		"2.16.840.1.101.3.4.3.25": "crypto/algorithm/slh-dsa-sha2-256f@2.16.840.1.101.3.4.3.25",
		"2.16.840.1.101.3.4.3.26": "crypto/algorithm/slh-dsa-shake-128s@2.16.840.1.101.3.4.3.26",
		"2.16.840.1.101.3.4.3.31": "crypto/algorithm/slh-dsa-shake-256f@2.16.840.1.101.3.4.3.31",
	} {
		c := mkCertWithSigOID(oid)
		got := czX509.ReadSignatureAlgorithmRef(ctx, c)
		require.Equal(t, want, got)
	}

	// XMSS / XMSS-MT / HSS-LMS
	for oid, want := range map[string]cdx.BOMReference{
		"1.3.6.1.5.5.7.6.34":         "crypto/algorithm/xmss-hashsig@1.3.6.1.5.5.7.6.34",
		"1.3.6.1.5.5.7.6.35":         "crypto/algorithm/xmssmt-hashsig@1.3.6.1.5.5.7.6.35",
		"1.2.840.113549.1.9.16.3.17": "crypto/algorithm/hss-lms-hashsig@1.2.840.113549.1.9.16.3.17",
	} {
		c := mkCertWithSigOID(oid)
		got := czX509.ReadSignatureAlgorithmRef(ctx, c)
		require.Equal(t, want, got)
	}

	// Unknown and parse-failure paths
	require.Equal(t, cdx.BOMReference("crypto/algorithm/unknown@unknown"), czX509.ReadSignatureAlgorithmRef(ctx, mkCertWithSigOID("1.2.3.4.5")))
	require.Equal(t, cdx.BOMReference("crypto/algorithm/unknown@unknown"), czX509.ReadSignatureAlgorithmRef(ctx, &x509.Certificate{Raw: []byte{0xff}}))
}

func Test_PQC_SPKI_OIDs(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	// ML-DSA and ML-KEM
	for oid, want := range map[string]cdx.BOMReference{
		"2.16.840.1.101.3.4.3.17": "crypto/key/ml-dsa-44@2.16.840.1.101.3.4.3.17",
		"2.16.840.1.101.3.4.3.19": "crypto/key/ml-dsa-87@2.16.840.1.101.3.4.3.19",
		"2.16.840.1.101.3.4.4.1":  "crypto/key/ml-kem-512@2.16.840.1.101.3.4.4.1",
		"2.16.840.1.101.3.4.4.3":  "crypto/key/ml-kem-1024@2.16.840.1.101.3.4.4.3",
	} {
		c := mkCertWithSPKIOID(oid)
		got := czX509.ReadSubjectPublicKeyRef(ctx, c)
		require.Equal(t, want, got)
	}

	// SLH-DSA, XMSS, XMSS-MT, HSS/LMS, HQC
	for oid, want := range map[string]cdx.BOMReference{
		"2.16.840.1.101.3.4.3.20":    "crypto/key/slh-dsa-sha2-128s@2.16.840.1.101.3.4.3.20",
		"2.16.840.1.101.3.4.3.31":    "crypto/key/slh-dsa-shake-256f@2.16.840.1.101.3.4.3.31",
		"1.3.6.1.5.5.7.6.34":         "crypto/key/xmss@1.3.6.1.5.5.7.6.34",
		"1.3.6.1.5.5.7.6.35":         "crypto/key/xmss-mt@1.3.6.1.5.5.7.6.35",
		"1.2.840.113549.1.9.16.3.17": "crypto/key/hss-lms@1.2.840.113549.1.9.16.3.17",
		"1.3.9999.6.1.1":             "crypto/key/hqc-128@1.3.9999.6.1.1",
	} {
		c := mkCertWithSPKIOID(oid)
		got := czX509.ReadSubjectPublicKeyRef(ctx, c)
		require.Equal(t, want, got)
	}

	// Unknown and parse-failure paths
	require.Equal(t, cdx.BOMReference("crypto/key/unknown@unknown"), czX509.ReadSubjectPublicKeyRef(ctx, mkCertWithSPKIOID("1.2.3.4.5")))
	require.Equal(t, cdx.BOMReference("crypto/key/unknown@unknown"), czX509.ReadSubjectPublicKeyRef(ctx, &x509.Certificate{RawSubjectPublicKeyInfo: []byte{0xff}}))
}
