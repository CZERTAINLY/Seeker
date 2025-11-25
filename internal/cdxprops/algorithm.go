package cdxprops

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Internal shared structure for algorithm metadata
type algorithmInfo struct {
	name                     string
	oid                      string
	paramSetID               string
	keySize                  int
	algorithmName            string
	cryptoFunctions          []cdx.CryptoFunction
	classicalSecurityLevel   int
	nistQuantumSecurityLevel int
}

// extractAlgorithmInfo is the unified internal function
func extractAlgorithmInfo(keyType string, key any) algorithmInfo {
	var meta algorithmInfo

	switch keyType {
	case "RSA":
		meta.oid = "1.2.840.113549.1.1.1"
		meta.cryptoFunctions = []cdx.CryptoFunction{
			cdx.CryptoFunctionEncapsulate,
			cdx.CryptoFunctionDecapsulate,
		}

		// Try to extract size from actual key if available
		if rsaKey, ok := key.(interface{ BitLen() int }); ok {
			meta.keySize = rsaKey.BitLen()
			meta.paramSetID = fmt.Sprintf("%d", meta.keySize)
			meta.name = fmt.Sprintf("RSA-%d", meta.keySize)
			meta.algorithmName = fmt.Sprintf("crypto/algorithm/rsa-%d", meta.keySize)
			switch meta.keySize {
			case 1024:
				meta.classicalSecurityLevel = 80
			case 2048:
				meta.classicalSecurityLevel = 112
			case 3072:
				meta.classicalSecurityLevel = 128
			case 4096:
				meta.classicalSecurityLevel = 152
			}
		} else {
			meta.name = "RSA"
			meta.algorithmName = "crypto/algorithm/rsa"
		}

	case "ECDSA":
		meta.cryptoFunctions = []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		}

		// Try to extract curve info
		type curveProvider interface {
			GetCurve() elliptic.Curve
		}

		if cp, ok := key.(curveProvider); ok && cp.GetCurve() != nil {
			curve := cp.GetCurve()
			curveName := curve.Params().Name
			meta.keySize = curve.Params().BitSize
			meta.paramSetID = curveName
			meta.name = fmt.Sprintf("ECDSA-%s", curveName)

			switch curveName {
			case "P-224":
				meta.oid = "1.2.840.10045.3.1.1"
				meta.classicalSecurityLevel = 80
			case "P-256":
				meta.oid = "1.2.840.10045.3.1.7"
				meta.classicalSecurityLevel = 128
			case "P-384":
				meta.oid = "1.3.132.0.34"
				meta.classicalSecurityLevel = 192
			case "P-521":
				meta.oid = "1.3.132.0.35"
				meta.classicalSecurityLevel = 256
			default:
				meta.oid = "1.2.840.10045.2.1"
			}
			meta.algorithmName = fmt.Sprintf("crypto/algorithm/ecdsa-%s", strings.ToLower(curveName))
		} else {
			meta.name = "ECDSA"
			meta.oid = "1.2.840.10045.2.1"
			meta.algorithmName = "crypto/algorithm/ecdsa"
		}

	case "Ed25519":
		meta.name = "Ed25519"
		meta.oid = "1.3.101.112"
		meta.paramSetID = "256"
		meta.keySize = 256
		meta.classicalSecurityLevel = 128
		meta.cryptoFunctions = []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		}
		meta.algorithmName = "crypto/algorithm/ed25519"

	case "DSA":
		meta.oid = "1.2.840.10040.4.1"
		meta.cryptoFunctions = []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		}

		if dsaKey, ok := key.(interface{ BitLen() int }); ok {
			meta.keySize = dsaKey.BitLen()
			switch dsaKey.BitLen() {
			case 1024:
				meta.classicalSecurityLevel = 80
			case 2048:
				meta.classicalSecurityLevel = 112
			case 3072:
				meta.classicalSecurityLevel = 128
			}
			meta.paramSetID = fmt.Sprintf("%d", meta.keySize)
			meta.name = fmt.Sprintf("DSA-%d", meta.keySize)
			meta.algorithmName = fmt.Sprintf("crypto/algorithm/dsa-%d", meta.keySize)
		} else {
			meta.name = "DSA"
			meta.algorithmName = "crypto/algorithm/dsa"
		}

	default:
		meta.name = "Unknown"
		meta.oid = "0.0.0.0"
		meta.algorithmName = "crypto/algorithm/unknown"
	}

	return meta
}

// Adapters to provide unified interfaces
type rsaKeyAdapter struct {
	key *rsa.PublicKey
}

func (a rsaKeyAdapter) BitLen() int {
	return a.key.N.BitLen()
}

type ecKeyAdapter struct {
	key *ecdsa.PublicKey
}

func (a ecKeyAdapter) GetCurve() elliptic.Curve {
	return a.key.Curve
}

type dsaKeyAdapter struct {
	key *dsa.PublicKey
}

func (a dsaKeyAdapter) BitLen() int {
	return a.key.P.BitLen()
}

func (i algorithmInfo) componentWOBomRef() cdx.Component {
	certLevel := []cdx.CryptoCertificationLevel{cdx.CryptoCertificationLevelNone}

	cryptoProps := &cdx.CryptoProperties{
		AssetType: cdx.CryptoAssetTypeAlgorithm,
		AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
			Primitive:                cdx.CryptoPrimitiveAE,
			ExecutionEnvironment:     cdx.CryptoExecutionEnvironmentSoftwarePlainRAM,
			CertificationLevel:       &certLevel,
			CryptoFunctions:          &i.cryptoFunctions,
			ClassicalSecurityLevel:   &i.classicalSecurityLevel,
			NistQuantumSecurityLevel: &i.nistQuantumSecurityLevel,
		},
	}

	if i.oid != "" {
		cryptoProps.OID = i.oid
	}

	if i.paramSetID != "" {
		cryptoProps.AlgorithmProperties.ParameterSetIdentifier = i.paramSetID
	}

	return cdx.Component{
		Type:             cdx.ComponentTypeCryptographicAsset,
		Name:             i.name,
		CryptoProperties: cryptoProps,
	}
}
