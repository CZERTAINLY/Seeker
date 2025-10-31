package cdxprops

import (
	"fmt"

	"github.com/CZERTAINLY/Seeker/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

var algoMap = map[string]cdx.CryptoAlgorithmProperties{
	"ecdsa-sha2-nistp256": {
		Primitive:              cdx.CryptoPrimitiveSignature,
		ParameterSetIdentifier: "nistp256@1.2.840.10045.3.1.7",
		Curve:                  "nistp256",
		CryptoFunctions:        &[]cdx.CryptoFunction{cdx.CryptoFunctionVerify},
	},
	"ecdsa-sha2-nistp384": {
		Primitive:              cdx.CryptoPrimitiveSignature,
		ParameterSetIdentifier: "nistp384@1.3.132.0.34",
		Curve:                  "nistp384",
		CryptoFunctions:        &[]cdx.CryptoFunction{cdx.CryptoFunctionVerify},
	},
	"ecdsa-sha2-nistp521": {
		Primitive:              cdx.CryptoPrimitiveSignature,
		ParameterSetIdentifier: "nistp521@1.3.132.0.35",
		Curve:                  "nistp521",
		CryptoFunctions:        &[]cdx.CryptoFunction{cdx.CryptoFunctionVerify},
	},
	"ssh-ed25519": {
		Primitive:              cdx.CryptoPrimitiveSignature,
		ParameterSetIdentifier: "ed25519@1.3.101.112",
		Curve:                  "ed25519",
		CryptoFunctions:        &[]cdx.CryptoFunction{cdx.CryptoFunctionVerify},
	},
	"rsa-sha2-256": {
		Primitive:              cdx.CryptoPrimitiveSignature,
		ParameterSetIdentifier: "rsa@1.2.840.113549.1.1.1",
		CryptoFunctions:        &[]cdx.CryptoFunction{cdx.CryptoFunctionVerify},
	},
	"rsa-sha2-512": {
		Primitive:              cdx.CryptoPrimitiveSignature,
		ParameterSetIdentifier: "rsa@1.2.840.113549.1.1.1",
		CryptoFunctions:        &[]cdx.CryptoFunction{cdx.CryptoFunctionVerify},
	},
	"ssh-rsa": { // legacy
		Primitive:              cdx.CryptoPrimitiveAE,
		ParameterSetIdentifier: "rsa@1.2.840.113549.1.1.1",
		CryptoFunctions:        &[]cdx.CryptoFunction{cdx.CryptoFunctionVerify},
	},
}

// ParseSSHAlgorithm returns CycloneDX crypto algorithm properties for a known SSH
// host key algorithm string. It reports ok=false if the algorithm is unsupported.
func ParseSSHAlgorithm(algo string) (cdx.CryptoAlgorithmProperties, bool) {
	p, ok := algoMap[algo]
	return p, ok
}

func ParseSSHHostKey(key model.SSHHostKey) (cdx.Component, error) {
	algoProp, ok := ParseSSHAlgorithm(key.Type)
	if !ok {
		return cdx.Component{}, fmt.Errorf("unsupported ssh algorithm %s", key.Type)
	}

	compo := cdx.Component{
		BOMRef: "crypto/ssh-hostkey/" + key.Type + "@" + key.Bits,
		Name:   key.Type,
		Type:   cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &algoProp,
			OID:                 algoProp.ParameterSetIdentifier,
		},
	}
	SetComponentProp(&compo, CzertainlyComponentSSHHostKeyContent, key.Key)
	SetComponentProp(&compo, CzertainlyComponentSSHHostKeyFingerprintContent, key.Fingerprint)
	return compo, nil
}
