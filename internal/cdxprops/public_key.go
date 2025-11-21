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
	var name string
	var oid string
	var paramSetID string
	var cryptoFunctions []cdx.CryptoFunction
	var keySize int
	var algorithmRef string

	switch pubKeyAlg {
	case x509.RSA:
		oid = "1.2.840.113549.1.1.1"
		cryptoFunctions = []cdx.CryptoFunction{
			cdx.CryptoFunctionEncapsulate,
			cdx.CryptoFunctionDecapsulate,
		}
		if key, ok := pubKey.(*rsa.PublicKey); ok {
			keySize = key.N.BitLen()
			paramSetID = fmt.Sprintf("%d", keySize)
			name = fmt.Sprintf("RSA-%d", keySize)
			algorithmRef = fmt.Sprintf("crypto/algorithm/rsa-%d@%s", keySize, oid)
		} else {
			name = "RSA"
			algorithmRef = fmt.Sprintf("crypto/algorithm/rsa@%s", oid)
		}

	case x509.ECDSA:
		cryptoFunctions = []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		}
		if key, ok := pubKey.(*ecdsa.PublicKey); ok && key.Curve != nil {
			curveName := key.Curve.Params().Name
			keySize = key.Curve.Params().BitSize
			paramSetID = curveName
			name = fmt.Sprintf("ECDSA-%s", curveName)

			// Set OID based on curve
			switch curveName {
			case "P-256":
				oid = "1.2.840.10045.3.1.7"
			case "P-384":
				oid = "1.3.132.0.34"
			case "P-521":
				oid = "1.3.132.0.35"
			}
			algorithmRef = fmt.Sprintf("crypto/algorithm/ecdsa-%s@%s", strings.ToLower(curveName), oid)
		} else {
			name = "ECDSA"
			oid = "1.2.840.10045.2.1"
			algorithmRef = fmt.Sprintf("crypto/algorithm/ecdsa@%s", oid)
		}

	case x509.Ed25519:
		name = "Ed25519"
		oid = "1.3.101.112"
		paramSetID = "256"
		cryptoFunctions = []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		}
		algorithmRef = fmt.Sprintf("crypto/algorithm/ed25519@%s", oid)

	case x509.DSA:
		oid = "1.2.840.10040.4.1"
		cryptoFunctions = []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		}
		if key, ok := pubKey.(*dsa.PublicKey); ok {
			keySize = key.P.BitLen()
			paramSetID = fmt.Sprintf("%d", keySize)
			name = fmt.Sprintf("DSA-%d", keySize)
			algorithmRef = fmt.Sprintf("crypto/algorithm/dsa-%d@%s", keySize, oid)
		} else {
			name = "DSA"
			algorithmRef = fmt.Sprintf("crypto/algorithm/dsa@%s", oid)
		}

	default:
		name = "Unknown"
		oid = "0.0.0.0"
		algorithmRef = fmt.Sprintf("crypto/algorithm/unknown@%s", oid)
	}

	// algorithm properties
	cryptoProps := &cdx.CryptoProperties{
		AssetType: cdx.CryptoAssetTypeAlgorithm,
		AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
			CryptoFunctions: &cryptoFunctions,
		},
	}

	if oid != "" {
		cryptoProps.OID = oid
	}

	if paramSetID != "" {
		cryptoProps.AlgorithmProperties.ParameterSetIdentifier = paramSetID
	}

	algo = cdx.Component{
		Type:             cdx.ComponentTypeCryptographicAsset,
		Name:             name,
		BOMRef:           algorithmRef,
		CryptoProperties: cryptoProps,
	}

	// public key properties
	var bomRef string
	if certBomRef != "" {
		bomRef = strings.Replace(certBomRef, "certificate", "key", 1)
	} else {
		bomRef = fmt.Sprintf("crypto/key/name@%s", c.hashPublicKey(pubKey))
	}

	relatedProps := &cdx.RelatedCryptoMaterialProperties{
		Type:         cdx.RelatedCryptoMaterialTypePublicKey,
		AlgorithmRef: cdx.BOMReference(algorithmRef),
	}

	if keySize > 0 {
		relatedProps.Size = &keySize
	}

	key = cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   name,
		BOMRef: bomRef,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			OID:                             oid,
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
