package cdxprops

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
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
		components = append(components, privateKeyToCDX(key, bundle.RawBlocks, i, location))
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
