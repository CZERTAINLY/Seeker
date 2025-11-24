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
type algorithmMetadata struct {
	name            string
	oid             string
	paramSetID      string
	keySize         int
	algorithmName   string
	cryptoFunctions []cdx.CryptoFunction
}

// extractAlgorithmMetadata is the unified internal function
func extractAlgorithmMetadata(keyType string, key any) algorithmMetadata {
	var meta algorithmMetadata

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
			case "P-256":
				meta.oid = "1.2.840.10045.3.1.7"
			case "P-384":
				meta.oid = "1.3.132.0.34"
			case "P-521":
				meta.oid = "1.3.132.0.35"
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
