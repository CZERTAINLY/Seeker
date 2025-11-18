package cdxprops

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// PEMBundleToCDX converts a PEM bundle to CycloneDX components
func PEMBundleToCDX(ctx context.Context, bundle model.PEMBundle, location string) ([]cdx.Component, error) {
	components := make([]cdx.Component, 0)
	var errs []error

	// Convert certificates
	for _, cert := range bundle.Certificates {
		compo, err := CertHitToComponent(ctx, cert)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		components = append(components, compo)
	}

	// Convert private keys
	for i, key := range bundle.PrivateKeys {
		components = append(components, privateKeyToCDX(key.Key, bundle.RawBlocks, i, location))
	}

	// Convert certificate requests
	for i, csr := range bundle.CertificateRequests {
		components = append(components, csrToCDX(csr, bundle.RawBlocks[findBlockIndex(bundle.RawBlocks, "CERTIFICATE REQUEST", i)], location))
	}

	// Convert public keys
	for i, pubKey := range bundle.PublicKeys {
		components = append(components, publicKeyToCDX(pubKey, bundle.RawBlocks[findBlockIndex(bundle.RawBlocks, "PUBLIC KEY", i)], location))
	}

	// Convert CRLs
	for i, crl := range bundle.CRLs {
		components = append(components, crlToCDX(crl, bundle.RawBlocks[findBlockIndex(bundle.RawBlocks, "X509 CRL", i)], location))
	}

	// try to parse unrecognized parts of a PEM
	for _, i := range slices.Sorted(maps.Keys(bundle.ParseErrors)) {
		parseErr := bundle.ParseErrors[i]
		block := bundle.RawBlocks[i]
		compo, err := analyzeParseError(block, parseErr)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		components = append(components, compo)
	}

	return components, errors.Join(errs...)
}

func privateKeyToCDX(key crypto.PrivateKey, blocks []model.PEMBlock, index int, location string) cdx.Component {
	keyType, algorithmRef, size := getPrivateKeyInfo(key)
	block := findPrivateKeyBlock(blocks, index)

	return cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		Name: fmt.Sprintf("%s Private Key", keyType),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type:         cdx.RelatedCryptoMaterialTypePrivateKey,
				AlgorithmRef: cdx.BOMReference(algorithmRef),
				Size:         &size,
				Format:       keyType,
			},
			OID: algorithmRef,
		},
		Properties: &[]cdx.Property{
			{Name: "location", Value: location},
			{Name: "pem_type", Value: block.Type},
			{Name: "order", Value: fmt.Sprintf("%d", block.Order)},
			{Name: "key_type", Value: keyType},
			{Name: "key_size", Value: fmt.Sprintf("%d", size)},
		},
	}
}

func csrToCDX(csr *x509.CertificateRequest, block model.PEMBlock, location string) cdx.Component {
	return cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		Name: fmt.Sprintf("CSR: %s", csr.Subject.CommonName),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type:  cdx.RelatedCryptoMaterialTypeOther,
				Value: string(pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes})),
			},
		},
		Properties: &[]cdx.Property{
			{Name: "location", Value: location},
			{Name: "pem_type", Value: block.Type},
			{Name: "order", Value: fmt.Sprintf("%d", block.Order)},
			{Name: "subject", Value: csr.Subject.String()},
		},
	}
}

func publicKeyToCDX(pubKey crypto.PublicKey, block model.PEMBlock, location string) cdx.Component {
	keyType, algorithmRef, size := getPublicKeyInfo(pubKey)

	return cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		Name: fmt.Sprintf("%s Public Key", keyType),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type:         cdx.RelatedCryptoMaterialTypePublicKey,
				AlgorithmRef: cdx.BOMReference(algorithmRef),
				Size:         &size,
				Format:       keyType,
			},
		},
		Properties: &[]cdx.Property{
			{Name: "location", Value: location},
			{Name: "pem_type", Value: block.Type},
			{Name: "order", Value: fmt.Sprintf("%d", block.Order)},
			{Name: "key_type", Value: keyType},
			{Name: "key_size", Value: fmt.Sprintf("%d", size)},
		},
	}
}

func crlToCDX(crl *x509.RevocationList, block model.PEMBlock, location string) cdx.Component {
	return cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		Name: "Certificate Revocation List",
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type:  cdx.RelatedCryptoMaterialTypeOther,
				Value: string(pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes})),
			},
		},
		Properties: &[]cdx.Property{
			{Name: "location", Value: location},
			{Name: "pem_type", Value: block.Type},
			{Name: "order", Value: fmt.Sprintf("%d", block.Order)},
			{Name: "issuer", Value: crl.Issuer.String()},
			{Name: "this_update", Value: crl.ThisUpdate.Format(time.RFC3339)},
			{Name: "next_update", Value: crl.NextUpdate.Format(time.RFC3339)},
			{Name: "revoked_count", Value: fmt.Sprintf("%d", len(crl.RevokedCertificateEntries))},
		},
	}
}

// Helper functions

func getPrivateKeyInfo(key crypto.PrivateKey) (keyType string, algorithmRef string, size int) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return "RSA", "RSA", k.N.BitLen()
	case *ecdsa.PrivateKey:
		return "ECDSA", fmt.Sprintf("ECDSA-%s", k.Curve.Params().Name), k.Curve.Params().BitSize
	case ed25519.PrivateKey:
		return "Ed25519", "Ed25519", 256
	default:
		return "Unknown", "Unknown", 0
	}
}

func getPublicKeyInfo(key crypto.PublicKey) (keyType string, algorithmRef string, size int) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return "RSA", "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", fmt.Sprintf("ECDSA-%s", k.Curve.Params().Name), k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", "Ed25519", 256
	default:
		return "Unknown", "Unknown", 0
	}
}

func findBlockIndex(blocks []model.PEMBlock, blockType string, occurrence int) int {
	count := 0
	for i, block := range blocks {
		if block.Type == blockType || (blockType == "CERTIFICATE REQUEST" && block.Type == "NEW CERTIFICATE REQUEST") {
			if count == occurrence {
				return i
			}
			count++
		}
	}
	return -1
}

func findPrivateKeyBlock(blocks []model.PEMBlock, index int) model.PEMBlock {
	privateKeyTypes := []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY"}
	count := 0
	for _, block := range blocks {
		for _, pkType := range privateKeyTypes {
			if block.Type == pkType {
				if count == index {
					return block
				}
				count++
				break
			}
		}
	}
	return model.PEMBlock{}
}

func analyzeParseError(block model.PEMBlock, parseErr error) (cdx.Component, error) {
	const mlkemPrefix = "2.16.840.1.101.3.4.3.18"
	if block.Type == "PRIVATE KEY" && strings.Contains(parseErr.Error(), mlkemPrefix) {
		compo, err := mlkemToComponent(block.Bytes)
		if err != nil {
			return cdx.Component{}, errors.Join(parseErr, err)
		}
		return compo, nil
	}
	return cdx.Component{}, parseErr
}

// ********** PQC support **********

// PKCS#8 PrivateKeyInfo structure
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// ML-KEM private key structure
type mlkemPrivateKey struct {
	Seed       []byte
	PrivateKey []byte
}

func mlkemToComponent(b []byte) (cdx.Component, error) {
	var pkcs8Key pkcs8
	_, err := asn1.Unmarshal(b, &pkcs8Key)
	if err != nil {
		return cdx.Component{}, fmt.Errorf("parsing PKCS#8 via ASN.1: %w", err)
	}

	var mlkemKey mlkemPrivateKey
	_, err = asn1.Unmarshal(pkcs8Key.PrivateKey, &mlkemKey)
	if err != nil {
		return cdx.Component{}, fmt.Errorf("parsing ML-KEM via ASN.1: %w", err)
	}

	var size int
	if len(mlkemKey.PrivateKey) >= 3168 {
		size = 1024
	} else if len(mlkemKey.PrivateKey) >= 2400 {
		size = 768
	} else {
		size = 512
	}

	compo := cdx.Component{
		BOMRef: string(spkiOIDRef[pkcs8Key.Algo.Algorithm.String()]),
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   "ML-KEM-" + strconv.Itoa(size),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type:   cdx.RelatedCryptoMaterialTypePrivateKey,
				Size:   &size,
				Format: "PEM",
			},
			OID: pkcs8Key.Algo.Algorithm.String(),
		},
	}
	return compo, nil
}
