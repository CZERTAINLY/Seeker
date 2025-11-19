package cdxprops_test

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/Seeker/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestPEMBundleToCDX(t *testing.T) {
	const location = "/test/bundle.pem"
	ctx := context.Background()

	// Generate test certificate
	selfSigned, err := cdxtest.CertBuilder{}.
		WithSignatureAlgorithm(x509.SHA256WithRSA).
		Generate()
	require.NoError(t, err)

	// Generate CSR
	csrKey, err := cdxtest.GenECPrivateKey(elliptic.P224())
	require.NoError(t, err)
	csr, _, err := cdxtest.GenCSR(csrKey)
	require.NoError(t, err)

	// Generate CRL
	crlCert, err := cdxtest.CertBuilder{}.
		WithIsCA(true).
		WithKeyUsage(x509.KeyUsageCRLSign | x509.KeyUsageCertSign).
		Generate()
	require.NoError(t, err)
	signer, ok := crlCert.Key.(crypto.Signer)
	require.True(t, ok)
	crl, _, err := cdxtest.GenCRL(crlCert.Cert, signer)
	require.NoError(t, err)

	// Generate public key
	pubKey, _, err := cdxtest.GenEd25519Keys()
	require.NoError(t, err)

	// Create comprehensive PEM bundle
	bundle := model.PEMBundle{
		Certificates: []model.CertHit{
			{
				Cert:     selfSigned.Cert,
				Source:   "PEM",
				Location: location,
			},
		},
		PrivateKeys: []model.PrivateKeyInfo{
			{
				Key:        selfSigned.Key,
				Type:       "RSA",
				Source:     "PEM",
				BlockIndex: -1,
			},
			{
				Key:        csrKey,
				Type:       "ECDSA",
				Source:     "PEM",
				BlockIndex: -1,
			},
		},
		CertificateRequests: []*x509.CertificateRequest{csr},
		PublicKeys:          []crypto.PublicKey{pubKey},
		CRLs:                []*x509.RevocationList{crl},
		RawBlocks:           []model.PEMBlock{},
		ParseErrors:         map[int]error{},
	}

	// Execute
	components, err := cdxprops.PEMBundleToCDX(ctx, bundle, location)
	require.NoError(t, err)

	// Verify we got all expected components
	// 1 certificate + 2 private keys + 1 CSR + 1 public key + 1 CRL = 6 components
	require.Len(t, components, 6)

	// Verify certificate component
	certComponents := filterByName(components, "CN=Test Cert")
	require.Len(t, certComponents, 1)
	certComp := certComponents[0]
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, certComp.Type)
	require.NotNil(t, certComp.CryptoProperties)
	require.Equal(t, cdx.CryptoAssetTypeCertificate, certComp.CryptoProperties.AssetType)

	// Verify RSA private key component
	rsaKeyComponents := filterByName(components, "RSA-2048")
	require.Len(t, rsaKeyComponents, 1)
	rsaKeyComp := rsaKeyComponents[0]
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, rsaKeyComp.Type)
	require.NotNil(t, rsaKeyComp.CryptoProperties)
	require.Equal(t, cdx.CryptoAssetTypeRelatedCryptoMaterial, rsaKeyComp.CryptoProperties.AssetType)
	require.NotNil(t, rsaKeyComp.CryptoProperties.RelatedCryptoMaterialProperties)
	require.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, rsaKeyComp.CryptoProperties.RelatedCryptoMaterialProperties.Type)
	require.Equal(t, "PEM", rsaKeyComp.CryptoProperties.RelatedCryptoMaterialProperties.Format)
	require.NotNil(t, rsaKeyComp.CryptoProperties.RelatedCryptoMaterialProperties.Size)
	require.Equal(t, 2048, *rsaKeyComp.CryptoProperties.RelatedCryptoMaterialProperties.Size)
	require.NoError(t, cdxtest.HasEvidencePath(rsaKeyComp, location))

	// Verify ECDSA private key component
	ecKeyComponents := filterByName(components, "ECDSA-224")
	require.Len(t, ecKeyComponents, 1)
	ecKeyComp := ecKeyComponents[0]
	require.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, ecKeyComp.CryptoProperties.RelatedCryptoMaterialProperties.Type)
	require.Contains(t, ecKeyComp.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef, "crypto/algorithm/ecdsa")

	// Verify CSR component
	csrComponents := filterByName(components, "CSR: Test CSR")
	require.Len(t, csrComponents, 1)
	csrComp := csrComponents[0]
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, csrComp.Type)
	require.Equal(t, cdx.RelatedCryptoMaterialTypeOther, csrComp.CryptoProperties.RelatedCryptoMaterialProperties.Type)
	requirePropertyValue(t, csrComp, "pem_type", "CSR")
	requirePropertyValue(t, csrComp, "subject", "CN=Test CSR,O=Test Org")

	// Verify public key component
	pubKeyComponents := filterByName(components, "Ed25519 Public Key")
	require.Len(t, pubKeyComponents, 1)
	pubKeyComp := pubKeyComponents[0]
	require.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, pubKeyComp.CryptoProperties.RelatedCryptoMaterialProperties.Type)
	require.Equal(t, "Ed25519", pubKeyComp.CryptoProperties.RelatedCryptoMaterialProperties.Format)
	require.Equal(t, 256, *pubKeyComp.CryptoProperties.RelatedCryptoMaterialProperties.Size)

	// Verify CRL component
	crlComponents := filterByName(components, "Certificate Revocation List")
	require.Len(t, crlComponents, 1)
	crlComp := crlComponents[0]
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, crlComp.Type)
	require.Equal(t, cdx.RelatedCryptoMaterialTypeOther, crlComp.CryptoProperties.RelatedCryptoMaterialProperties.Type)
	requirePropertyValue(t, crlComp, "location", location)
	requirePropertyValue(t, crlComp, "revoked_count", "1")

	// Verify all components have evidence location
	for _, comp := range components {
		require.NotNil(t, comp.Evidence)
		require.NotNil(t, comp.Evidence.Occurrences)
		require.NotEmpty(t, *comp.Evidence.Occurrences)
		require.Equal(t, location, (*comp.Evidence.Occurrences)[0].Location)
	}
}

func TestPrivateKeyInfo(t *testing.T) {
	tests := []struct {
		name        string
		key         crypto.PrivateKey
		wantKeyType string
		wantAlgoRef string
		wantSize    int
	}{
		{
			name:        "RSA 2048",
			key:         mustGenerateRSAKey(t, 2048),
			wantKeyType: "RSA",
			wantAlgoRef: "crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1",
			wantSize:    2048,
		},
		{
			name:        "RSA 4096",
			key:         mustGenerateRSAKey(t, 4096),
			wantKeyType: "RSA",
			wantAlgoRef: "crypto/algorithm/rsa-4096@1.2.840.113549.1.1.1",
			wantSize:    4096,
		},
		{
			name:        "ECDSA P-224",
			key:         mustGenerateECDSAKey(t, elliptic.P224()),
			wantKeyType: "ECDSA",
			wantAlgoRef: "crypto/algorithm/ecdsa-p224@1.2.840.10045.3.1.1",
			wantSize:    224,
		},
		{
			name:        "ECDSA P-384",
			key:         mustGenerateECDSAKey(t, elliptic.P384()),
			wantKeyType: "ECDSA",
			wantAlgoRef: "crypto/algorithm/ecdsa-p384@1.3.132.0.34",
			wantSize:    384,
		},
		{
			name:        "ECDSA P-521",
			key:         mustGenerateECDSAKey(t, elliptic.P521()),
			wantKeyType: "ECDSA",
			wantAlgoRef: "crypto/algorithm/ecdsa-p521@1.3.132.0.35",
			wantSize:    521,
		},
		{
			name:        "Ed25519",
			key:         mustGenerateEd25519Key(t),
			wantKeyType: "Ed25519",
			wantAlgoRef: "crypto/algorithm/ed25519@1.3.101.112",
			wantSize:    256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyType, algorithmRef, size := cdxprops.PrivateKeyInfo(tt.key)

			require.Equal(t, tt.wantKeyType, keyType, "keyType mismatch")
			require.Equal(t, tt.wantAlgoRef, algorithmRef, "algorithmRef mismatch")
			require.Equal(t, tt.wantSize, size, "size mismatch")
		})
	}
}

// Helper function to filter components by name
func filterByName(components []cdx.Component, name string) []cdx.Component {
	var result []cdx.Component
	for _, comp := range components {
		if comp.Name == name {
			result = append(result, comp)
		}
	}
	return result
}

// Helper function to verify property value
func requirePropertyValue(t *testing.T, comp cdx.Component, name, expectedValue string) {
	t.Helper()
	require.NotNil(t, comp.Properties)
	for _, prop := range *comp.Properties {
		if prop.Name == name {
			require.Equal(t, expectedValue, prop.Value)
			return
		}
	}
	require.Failf(t, "property not found", "property %s not found in component %s", name, comp.Name)
}

func mustGenerateRSAKey(t *testing.T, size int) crypto.PrivateKey {
	t.Helper()
	key, err := cdxtest.GenRSAPrivateKey(size)
	require.NoError(t, err)
	return key
}

func mustGenerateECDSAKey(t *testing.T, curve elliptic.Curve) crypto.PrivateKey {
	t.Helper()
	key, err := cdxtest.GenECPrivateKey(curve)
	require.NoError(t, err)
	return key
}

func mustGenerateEd25519Key(t *testing.T) crypto.PrivateKey {
	t.Helper()
	_, key, err := cdxtest.GenEd25519Keys()
	require.NoError(t, err)
	return key
}
