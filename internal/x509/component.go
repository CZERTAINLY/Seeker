package x509

import (
	"context"
	"crypto/dsa" //nolint:staticcheck // seeker is going to recognize even obsoleted crypto
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

// toComponent converts an X.509 certificate to a CycloneDX component
func toComponent(ctx context.Context, cert *x509.Certificate, path string, source string) (cdx.Component, error) {
	absPath, _ := filepath.Abs(path)

	c := cdx.Component{
		Type:    cdx.ComponentTypeCryptographicAsset,
		Name:    cert.Subject.String(),
		Version: cert.SerialNumber.String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeCertificate,
			CertificateProperties: &cdx.CertificateProperties{
				SubjectName:           cert.Subject.String(),
				IssuerName:            cert.Issuer.String(),
				NotValidBefore:        cert.NotBefore.Format(time.RFC3339),
				NotValidAfter:         cert.NotAfter.Format(time.RFC3339),
				SignatureAlgorithmRef: readSignatureAlgorithmRef(ctx, cert),
				SubjectPublicKeyRef:   readSubjectPublicKeyRef(ctx, cert),
				CertificateFormat:     "X.509",
				CertificateExtension:  filepath.Ext(path),
			},
		},
	}

	cdxprops.SetComponentProp(&c, cdxprops.CzertainlyComponentCertificateSourceFormat, source)
	cdxprops.SetComponentProp(&c, cdxprops.CzertainlyComponentCertificateBase64Content, base64.StdEncoding.EncodeToString(cert.Raw))
	cdxprops.AddEvidenceLocation(&c, absPath)

	return c, nil
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

func readSignatureAlgorithmRef(ctx context.Context, cert *x509.Certificate) cdx.BOMReference {
	switch cert.SignatureAlgorithm {
	case x509.MD5WithRSA:
		return "crypto/algorithm/md5-rsa@1.2.840.113549.1.1.4"
	case x509.SHA1WithRSA:
		return "crypto/algorithm/sha-1-rsa@1.2.840.113549.1.1.5"
	case x509.SHA256WithRSA:
		return "crypto/algorithm/sha-256-rsa@1.2.840.113549.1.1.11"
	case x509.SHA384WithRSA:
		return "crypto/algorithm/sha-384-rsa@1.2.840.113549.1.1.12"
	case x509.SHA512WithRSA:
		return "crypto/algorithm/sha-512-rsa@1.2.840.113549.1.1.13"
	case x509.DSAWithSHA1:
		return "crypto/algorithm/sha-1-dsa@1.2.840.10040.4.3"
	case x509.DSAWithSHA256:
		return "crypto/algorithm/sha-256-dsa@2.16.840.1.101.3.4.3.2"
	case x509.ECDSAWithSHA1:
		return "crypto/algorithm/sha-1-ecdsa@1.2.840.10045.4.1"
	case x509.ECDSAWithSHA256:
		return "crypto/algorithm/sha-256-ecdsa@1.2.840.10045.4.3.2"
	case x509.ECDSAWithSHA384:
		return "crypto/algorithm/sha-384-ecdsa@1.2.840.10045.4.3.3"
	case x509.ECDSAWithSHA512:
		return "crypto/algorithm/sha-512-ecdsa@1.2.840.10045.4.3.4"
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return "crypto/algorithm/rsassa-pss@1.2.840.113549.1.1.10"
	case x509.PureEd25519:
		return "crypto/algorithm/ed25519@1.3.101.112"
	default:
		// For PQC and unknown algorithms, parse OID below
	}

	// If we get here, it’s likely PQC (or another unknown). Parse the outer certificate to get the OID.
	type certOuter struct {
		TBSCert   asn1.RawValue
		SigAlg    algorithmIdentifier
		Signature asn1.BitString
	}
	var outer certOuter
	if _, err := asn1.Unmarshal(cert.Raw, &outer); err != nil {
		slog.DebugContext(ctx, "Failed to unmarshal outer certificate", "error", err)
		return "crypto/algorithm/unknown@unknown"
	}
	oid := outer.SigAlg.Algorithm.String()

	// ---- NIST PQC signature algorithms (FIPS 204/205) ----
	// ML-DSA (Dilithium) — signatureAlgorithm OIDs
	switch oid {
	case "2.16.840.1.101.3.4.3.17":
		return "crypto/algorithm/ml-dsa-44@2.16.840.1.101.3.4.3.17"
	case "2.16.840.1.101.3.4.3.18":
		return "crypto/algorithm/ml-dsa-65@2.16.840.1.101.3.4.3.18"
	case "2.16.840.1.101.3.4.3.19":
		return "crypto/algorithm/ml-dsa-87@2.16.840.1.101.3.4.3.19"

	// SLH-DSA (SPHINCS+) — SHA2 & SHAKE variants
	case "2.16.840.1.101.3.4.3.20":
		return "crypto/algorithm/slh-dsa-sha2-128s@2.16.840.1.101.3.4.3.20"
	case "2.16.840.1.101.3.4.3.21":
		return "crypto/algorithm/slh-dsa-sha2-128f@2.16.840.1.101.3.4.3.21"
	case "2.16.840.1.101.3.4.3.22":
		return "crypto/algorithm/slh-dsa-sha2-192s@2.16.840.1.101.3.4.3.22"
	case "2.16.840.1.101.3.4.3.23":
		return "crypto/algorithm/slh-dsa-sha2-192f@2.16.840.1.101.3.4.3.23"
	case "2.16.840.1.101.3.4.3.24":
		return "crypto/algorithm/slh-dsa-sha2-256s@2.16.840.1.101.3.4.3.24"
	case "2.16.840.1.101.3.4.3.25":
		return "crypto/algorithm/slh-dsa-sha2-256f@2.16.840.1.101.3.4.3.25"
	case "2.16.840.1.101.3.4.3.26":
		return "crypto/algorithm/slh-dsa-shake-128s@2.16.840.1.101.3.4.3.26"
	case "2.16.840.1.101.3.4.3.27":
		return "crypto/algorithm/slh-dsa-shake-128f@2.16.840.1.101.3.4.3.27"
	case "2.16.840.1.101.3.4.3.28":
		return "crypto/algorithm/slh-dsa-shake-192s@2.16.840.1.101.3.4.3.28"
	case "2.16.840.1.101.3.4.3.29":
		return "crypto/algorithm/slh-dsa-shake-192f@2.16.840.1.101.3.4.3.29"
	case "2.16.840.1.101.3.4.3.30":
		return "crypto/algorithm/slh-dsa-shake-256s@2.16.840.1.101.3.4.3.30"
	case "2.16.840.1.101.3.4.3.31":
		return "crypto/algorithm/slh-dsa-shake-256f@2.16.840.1.101.3.4.3.31"
	}

	// ---- IETF stateful hash-based signatures in X.509 (RFC 9802 / RFC 9708) ----
	switch oid {
	// HSS/LMS (uses id-alg-hss-lms-hashsig)
	case "1.2.840.113549.1.9.16.3.17":
		return "crypto/algorithm/hss-lms-hashsig@1.2.840.113549.1.9.16.3.17"
	// XMSS and XMSS^MT (PKIX algorithms arc)
	case "1.3.6.1.5.5.7.6.34":
		return "crypto/algorithm/xmss-hashsig@1.3.6.1.5.5.7.6.34"
	case "1.3.6.1.5.5.7.6.35":
		return "crypto/algorithm/xmssmt-hashsig@1.3.6.1.5.5.7.6.35"
	}

	// Unknown OID — return empty so caller can decide what to do
	slog.DebugContext(ctx, "Unknown signature algorithm OID", "oid", oid)
	return "crypto/algorithm/unknown@unknown"
}

func readSubjectPublicKeyRef(ctx context.Context, cert *x509.Certificate) cdx.BOMReference {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return cdx.BOMReference(fmt.Sprintf("crypto/key/rsa-%d@1.2.840.113549.1.1.1", pub.N.BitLen()))
	case *ecdsa.PublicKey:
		switch pub.Params().BitSize {
		case 256:
			return "crypto/key/ecdsa-p256@1.2.840.10045.3.1.7"
		case 384:
			return "crypto/key/ecdsa-p384@1.3.132.0.34"
		case 521:
			return "crypto/key/ecdsa-p521@1.3.132.0.35"
		default:
			return "crypto/key/ecdsa-unknown@1.2.840.10045.2.1"
		}
	case ed25519.PublicKey:
		return "crypto/key/ed25519-256@1.3.101.112"
	case *dsa.PublicKey:
		return cdx.BOMReference(fmt.Sprintf("crypto/key/dsa-%d@1.2.840.10040.4.1", pub.P.BitLen()))
	}

	// SubjectPublicKeyInfo  ::=  SEQUENCE  { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
	type spki struct {
		Algorithm     algorithmIdentifier
		SubjectPubKey asn1.BitString
	}

	// --- PQC & other: detect by OID in SubjectPublicKeyInfo.algorithm.algorithm ---
	var info spki
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &info); err != nil {
		slog.DebugContext(ctx, "Failed to unmarshal SubjectPublicKeyInfo", "error", err)
		return "crypto/key/unknown@unknown"
	}
	oid := info.Algorithm.Algorithm.String()

	// NIST ML-DSA (FIPS 204) — pure ML-DSA (a.k.a. Dilithium): 44/65/87
	if ref, ok := map[string]cdx.BOMReference{
		"2.16.840.1.101.3.4.3.17": "crypto/key/ml-dsa-44@2.16.840.1.101.3.4.3.17",
		"2.16.840.1.101.3.4.3.18": "crypto/key/ml-dsa-65@2.16.840.1.101.3.4.3.18",
		"2.16.840.1.101.3.4.3.19": "crypto/key/ml-dsa-87@2.16.840.1.101.3.4.3.19",
	}[oid]; ok {
		return ref
	}

	// NIST ML-KEM (FIPS 203) — Kyber: 512/768/1024
	if ref, ok := map[string]cdx.BOMReference{
		"2.16.840.1.101.3.4.4.1": "crypto/key/ml-kem-512@2.16.840.1.101.3.4.4.1",
		"2.16.840.1.101.3.4.4.2": "crypto/key/ml-kem-768@2.16.840.1.101.3.4.4.2",
		"2.16.840.1.101.3.4.4.3": "crypto/key/ml-kem-1024@2.16.840.1.101.3.4.4.3",
	}[oid]; ok {
		return ref
	}

	// NIST SLH-DSA (FIPS 205) — SPHINCS+ (SHA2 or SHAKE; small/fast; 128/192/256)
	if ref, ok := map[string]cdx.BOMReference{
		// SHA2
		"2.16.840.1.101.3.4.3.20": "crypto/key/slh-dsa-sha2-128s@2.16.840.1.101.3.4.3.20",
		"2.16.840.1.101.3.4.3.21": "crypto/key/slh-dsa-sha2-128f@2.16.840.1.101.3.4.3.21",
		"2.16.840.1.101.3.4.3.22": "crypto/key/slh-dsa-sha2-192s@2.16.840.1.101.3.4.3.22",
		"2.16.840.1.101.3.4.3.23": "crypto/key/slh-dsa-sha2-192f@2.16.840.1.101.3.4.3.23",
		"2.16.840.1.101.3.4.3.24": "crypto/key/slh-dsa-sha2-256s@2.16.840.1.101.3.4.3.24",
		"2.16.840.1.101.3.4.3.25": "crypto/key/slh-dsa-sha2-256f@2.16.840.1.101.3.4.3.25",
		// SHAKE
		"2.16.840.1.101.3.4.3.26": "crypto/key/slh-dsa-shake-128s@2.16.840.1.101.3.4.3.26",
		"2.16.840.1.101.3.4.3.27": "crypto/key/slh-dsa-shake-128f@2.16.840.1.101.3.4.3.27",
		"2.16.840.1.101.3.4.3.28": "crypto/key/slh-dsa-shake-192s@2.16.840.1.101.3.4.3.28",
		"2.16.840.1.101.3.4.3.29": "crypto/key/slh-dsa-shake-192f@2.16.840.1.101.3.4.3.29",
		"2.16.840.1.101.3.4.3.30": "crypto/key/slh-dsa-shake-256s@2.16.840.1.101.3.4.3.30",
		"2.16.840.1.101.3.4.3.31": "crypto/key/slh-dsa-shake-256f@2.16.840.1.101.3.4.3.31",
	}[oid]; ok {
		return ref
	}

	slog.DebugContext(ctx, "Unknown public key algorithm OID", "oid", oid)
	return "crypto/key/unknown@unknown"
}
