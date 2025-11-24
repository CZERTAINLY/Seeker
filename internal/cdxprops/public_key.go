package cdxprops

import (
	"context"
	"crypto"
	"crypto/dsa" //nolint: staticcheck
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// publicKeyAlgComponent creates a CycloneDX component for a public key algorithm
func (c Converter) publicKeyComponents(_ context.Context, certBomRef string, pubKeyAlg x509.PublicKeyAlgorithm, pubKey crypto.PublicKey) (algo, key cdx.Component) {
	meta := publicKeyAlgorithmMetadata(pubKeyAlg, pubKey)

	// algorithm properties
	cryptoProps := &cdx.CryptoProperties{
		AssetType: cdx.CryptoAssetTypeAlgorithm,
		AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
			CryptoFunctions: &meta.cryptoFunctions,
		},
	}

	if meta.oid != "" {
		cryptoProps.OID = meta.oid
	}

	if meta.paramSetID != "" {
		cryptoProps.AlgorithmProperties.ParameterSetIdentifier = meta.paramSetID
	}

	algo = cdx.Component{
		Type:             cdx.ComponentTypeCryptographicAsset,
		Name:             meta.name,
		CryptoProperties: cryptoProps,
	}
	c.BOMRefHash(&algo, meta.algorithmName)

	// public key properties
	var bomRef string
	if certBomRef != "" {
		bomRef = strings.Replace(certBomRef, "certificate", "key", 1)
	} else {
		bomRef = fmt.Sprintf("crypto/key/name@%s", c.hashPublicKey(pubKey))
	}

	relatedProps := &cdx.RelatedCryptoMaterialProperties{
		Type:         cdx.RelatedCryptoMaterialTypePublicKey,
		AlgorithmRef: cdx.BOMReference(meta.algorithmName),
	}

	if meta.keySize > 0 {
		relatedProps.Size = &meta.keySize
	}

	key = cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   meta.name,
		BOMRef: bomRef,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			OID:                             meta.oid,
			RelatedCryptoMaterialProperties: relatedProps,
		},
	}
	return
}

func (c Converter) hashPublicKey(pubKey crypto.PublicKey) string {
	// Marshal to PKIX/SPKI format (standard DER encoding)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return ""
	}
	// Hash the bytes
	return c.bomRefHasher(pubKeyBytes)
}

func publicKeyAlgorithmMetadata(pubKeyAlg x509.PublicKeyAlgorithm, pubKey crypto.PublicKey) algorithmMetadata {
	var keyType string
	var key any

	switch pubKeyAlg {
	case x509.RSA:
		keyType = "RSA"
		if rsaKey, ok := pubKey.(*rsa.PublicKey); ok {
			key = rsaKeyAdapter{rsaKey}
		}
	case x509.ECDSA:
		keyType = "ECDSA"
		if ecKey, ok := pubKey.(*ecdsa.PublicKey); ok {
			key = ecKeyAdapter{ecKey}
		}
	case x509.Ed25519:
		keyType = "Ed25519"
	case x509.DSA:
		keyType = "DSA"
		if dsaKey, ok := pubKey.(*dsa.PublicKey); ok {
			key = dsaKeyAdapter{dsaKey}
		}
	default:
		keyType = "Unknown"
	}

	return extractAlgorithmMetadata(keyType, key)
}
