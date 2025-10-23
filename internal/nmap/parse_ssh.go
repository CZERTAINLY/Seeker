package nmap

import cdx "github.com/CycloneDX/cyclonedx-go"

var algoMap = map[string]cdx.CryptoAlgorithmProperties{
	"ecdsa-sha2-nistp256": {
		Primitive:              cdx.CryptoPrimitiveAE,
		ParameterSetIdentifier: "nistp256@1.2.840.10045.3.1.7",
		Curve:                  "nistp256",
		CryptoFunctions:        &[]cdx.CryptoFunction{cdx.CryptoFunctionVerify},
	},
}

// ParseSSHAlgorithm returns CycloneDX crypto algorithm properties for a known SSH
// host key algorithm string. It reports ok=false if the algorithm is unsupported.
func ParseSSHAlgorithm(algo string) (cdx.CryptoAlgorithmProperties, bool) {
	p, ok := algoMap[algo]
	return p, ok
}
