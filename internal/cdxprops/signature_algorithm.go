package cdxprops

import (
	"crypto/x509"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Classic (non-PQC) signature algorithms mapped from Go’s enum.
var sigAlgRef = map[x509.SignatureAlgorithm]cdx.BOMReference{
	x509.MD5WithRSA:       "crypto/algorithm/md5-rsa@1.2.840.113549.1.1.4",
	x509.SHA1WithRSA:      "crypto/algorithm/sha-1-rsa@1.2.840.113549.1.1.5",
	x509.SHA256WithRSA:    "crypto/algorithm/sha-256-rsa@1.2.840.113549.1.1.11",
	x509.SHA384WithRSA:    "crypto/algorithm/sha-384-rsa@1.2.840.113549.1.1.12",
	x509.SHA512WithRSA:    "crypto/algorithm/sha-512-rsa@1.2.840.113549.1.1.13",
	x509.DSAWithSHA1:      "crypto/algorithm/sha-1-dsa@1.2.840.10040.4.3",
	x509.DSAWithSHA256:    "crypto/algorithm/sha-256-dsa@2.16.840.1.101.3.4.3.2",
	x509.ECDSAWithSHA1:    "crypto/algorithm/sha-1-ecdsa@1.2.840.10045.4.1",
	x509.ECDSAWithSHA256:  "crypto/algorithm/sha-256-ecdsa@1.2.840.10045.4.3.2",
	x509.ECDSAWithSHA384:  "crypto/algorithm/sha-384-ecdsa@1.2.840.10045.4.3.3",
	x509.ECDSAWithSHA512:  "crypto/algorithm/sha-512-ecdsa@1.2.840.10045.4.3.4",
	x509.SHA256WithRSAPSS: "crypto/algorithm/rsassa-pss@1.2.840.113549.1.1.10",
	x509.SHA384WithRSAPSS: "crypto/algorithm/rsassa-pss@1.2.840.113549.1.1.10",
	x509.SHA512WithRSAPSS: "crypto/algorithm/rsassa-pss@1.2.840.113549.1.1.10",
	x509.PureEd25519:      "crypto/algorithm/ed25519@1.3.101.112",
}

// PQC signature AlgorithmIdentifier OIDs (outer signatureAlgorithm).
var pqcSigOIDRef = map[string]cdx.BOMReference{
	// ML-DSA (FIPS 204)
	"2.16.840.1.101.3.4.3.17": "crypto/algorithm/ml-dsa-44@2.16.840.1.101.3.4.3.17",
	"2.16.840.1.101.3.4.3.18": "crypto/algorithm/ml-dsa-65@2.16.840.1.101.3.4.3.18",
	"2.16.840.1.101.3.4.3.19": "crypto/algorithm/ml-dsa-87@2.16.840.1.101.3.4.3.19",

	// SLH-DSA (FIPS 205) — SHA2
	"2.16.840.1.101.3.4.3.20": "crypto/algorithm/slh-dsa-sha2-128s@2.16.840.1.101.3.4.3.20",
	"2.16.840.1.101.3.4.3.21": "crypto/algorithm/slh-dsa-sha2-128f@2.16.840.1.101.3.4.3.21",
	"2.16.840.1.101.3.4.3.22": "crypto/algorithm/slh-dsa-sha2-192s@2.16.840.1.101.3.4.3.22",
	"2.16.840.1.101.3.4.3.23": "crypto/algorithm/slh-dsa-sha2-192f@2.16.840.1.101.3.4.3.23",
	"2.16.840.1.101.3.4.3.24": "crypto/algorithm/slh-dsa-sha2-256s@2.16.840.1.101.3.4.3.24",
	"2.16.840.1.101.3.4.3.25": "crypto/algorithm/slh-dsa-sha2-256f@2.16.840.1.101.3.4.3.25",
	// SLH-DSA (FIPS 205) — SHAKE
	"2.16.840.1.101.3.4.3.26": "crypto/algorithm/slh-dsa-shake-128s@2.16.840.1.101.3.4.3.26",
	"2.16.840.1.101.3.4.3.27": "crypto/algorithm/slh-dsa-shake-128f@2.16.840.1.101.3.4.3.27",
	"2.16.840.1.101.3.4.3.28": "crypto/algorithm/slh-dsa-shake-192s@2.16.840.1.101.3.4.3.28",
	"2.16.840.1.101.3.4.3.29": "crypto/algorithm/slh-dsa-shake-192f@2.16.840.1.101.3.4.3.29",
	"2.16.840.1.101.3.4.3.30": "crypto/algorithm/slh-dsa-shake-256s@2.16.840.1.101.3.4.3.30",
	"2.16.840.1.101.3.4.3.31": "crypto/algorithm/slh-dsa-shake-256f@2.16.840.1.101.3.4.3.31",

	// IETF stateful hash-based signatures in X.509
	"1.2.840.113549.1.9.16.3.17": "crypto/algorithm/hss-lms-hashsig@1.2.840.113549.1.9.16.3.17", // HSS/LMS
	"1.3.6.1.5.5.7.6.34":         "crypto/algorithm/xmss-hashsig@1.3.6.1.5.5.7.6.34",            // XMSS
	"1.3.6.1.5.5.7.6.35":         "crypto/algorithm/xmssmt-hashsig@1.3.6.1.5.5.7.6.35",          // XMSS^MT
}

// Public-key OIDs seen in SubjectPublicKeyInfo.algorithm (includes KEMs).
var spkiOIDRef = map[string]cdx.BOMReference{
	// ML-DSA (same OIDs as signature; appears as key type too)
	"2.16.840.1.101.3.4.3.17": "crypto/key/ml-dsa-44@2.16.840.1.101.3.4.3.17",
	"2.16.840.1.101.3.4.3.18": "crypto/key/ml-dsa-65@2.16.840.1.101.3.4.3.18",
	"2.16.840.1.101.3.4.3.19": "crypto/key/ml-dsa-87@2.16.840.1.101.3.4.3.19",

	// ML-KEM (FIPS 203)
	"2.16.840.1.101.3.4.4.1": "crypto/key/ml-kem-512@2.16.840.1.101.3.4.4.1",
	"2.16.840.1.101.3.4.4.2": "crypto/key/ml-kem-768@2.16.840.1.101.3.4.4.2",
	"2.16.840.1.101.3.4.4.3": "crypto/key/ml-kem-1024@2.16.840.1.101.3.4.4.3",

	// SLH-DSA (FIPS 205)
	"2.16.840.1.101.3.4.3.20": "crypto/key/slh-dsa-sha2-128s@2.16.840.1.101.3.4.3.20",
	"2.16.840.1.101.3.4.3.21": "crypto/key/slh-dsa-sha2-128f@2.16.840.1.101.3.4.3.21",
	"2.16.840.1.101.3.4.3.22": "crypto/key/slh-dsa-sha2-192s@2.16.840.1.101.3.4.3.22",
	"2.16.840.1.101.3.4.3.23": "crypto/key/slh-dsa-sha2-192f@2.16.840.1.101.3.4.3.23",
	"2.16.840.1.101.3.4.3.24": "crypto/key/slh-dsa-sha2-256s@2.16.840.1.101.3.4.3.24",
	"2.16.840.1.101.3.4.3.25": "crypto/key/slh-dsa-sha2-256f@2.16.840.1.101.3.4.3.25",
	"2.16.840.1.101.3.4.3.26": "crypto/key/slh-dsa-shake-128s@2.16.840.1.101.3.4.3.26",
	"2.16.840.1.101.3.4.3.27": "crypto/key/slh-dsa-shake-128f@2.16.840.1.101.3.4.3.27",
	"2.16.840.1.101.3.4.3.28": "crypto/key/slh-dsa-shake-192s@2.16.840.1.101.3.4.3.28",
	"2.16.840.1.101.3.4.3.29": "crypto/key/slh-dsa-shake-192f@2.16.840.1.101.3.4.3.29",
	"2.16.840.1.101.3.4.3.30": "crypto/key/slh-dsa-shake-256s@2.16.840.1.101.3.4.3.30",
	"2.16.840.1.101.3.4.3.31": "crypto/key/slh-dsa-shake-256f@2.16.840.1.101.3.4.3.31",

	// XMSS / XMSS-MT (IETF, same OIDs show in SPKI)
	"1.3.6.1.5.5.7.6.34": "crypto/key/xmss@1.3.6.1.5.5.7.6.34",
	"1.3.6.1.5.5.7.6.35": "crypto/key/xmss-mt@1.3.6.1.5.5.7.6.35",

	// HSS/LMS (IETF)
	"1.2.840.113549.1.9.16.3.17": "crypto/key/hss-lms@1.2.840.113549.1.9.16.3.17",

	// HQC (ISO/ETSI — commonly used OIDs)
	"1.3.9999.6.1.1": "crypto/key/hqc-128@1.3.9999.6.1.1",
	"1.3.9999.6.1.2": "crypto/key/hqc-192@1.3.9999.6.1.2",
	"1.3.9999.6.1.3": "crypto/key/hqc-256@1.3.9999.6.1.3",
}

func buildSignatureAlgorithmProperties(sigAlg x509.SignatureAlgorithm) []cdx.Property {
	var props []cdx.Property

	// Algorithm name
	algName := sigAlg.String()
	if algName != "" {
		props = append(props, cdx.Property{
			Name:  "algorithm",
			Value: algName,
		})
	}

	// Algorithm type and hash function
	algType, hashFunc := getAlgorithmInfo(sigAlg)
	if algType != "" {
		props = append(props, cdx.Property{
			Name:  "algorithmType",
			Value: algType,
		})
	}
	if hashFunc != "" {
		props = append(props, cdx.Property{
			Name:  "hashFunction",
			Value: hashFunc,
		})
	}

	return props
}

// getAlgorithmInfo returns the algorithm type and hash function for a signature algorithm
func getAlgorithmInfo(sigAlg x509.SignatureAlgorithm) (algType, hashFunc string) {
	switch sigAlg {
	case x509.MD2WithRSA:
		return "RSA", "MD2"
	case x509.MD5WithRSA:
		return "RSA", "MD5"
	case x509.SHA1WithRSA:
		return "RSA", "SHA1"
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS:
		return "RSA", "SHA256"
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS:
		return "RSA", "SHA384"
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
		return "RSA", "SHA512"
	case x509.ECDSAWithSHA1:
		return "ECDSA", "SHA1"
	case x509.ECDSAWithSHA256:
		return "ECDSA", "SHA256"
	case x509.ECDSAWithSHA384:
		return "ECDSA", "SHA384"
	case x509.ECDSAWithSHA512:
		return "ECDSA", "SHA512"
	case x509.DSAWithSHA1:
		return "DSA", "SHA1"
	case x509.DSAWithSHA256:
		return "DSA", "SHA256"
	case x509.PureEd25519:
		return "Ed25519", ""
	default:
		return "", ""
	}
}
