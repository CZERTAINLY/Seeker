package cdxprops

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

	"github.com/CZERTAINLY/Seeker/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ---------- constants & shared lookups ----------

const (
	refUnknownKey       cdx.BOMReference = "crypto/key/unknown@unknown"
	refUnknownAlgorithm cdx.BOMReference = "crypto/algorithm/unknown@unknown"
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

// ---------- ASN.1 helpers (declared once) ----------

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type certOuter struct {
	TBSCert   asn1.RawValue
	SigAlg    algorithmIdentifier
	Signature asn1.BitString
}

type spki struct {
	Algorithm     algorithmIdentifier
	SubjectPubKey asn1.BitString
}

func sigAlgOID(cert *x509.Certificate) (string, bool) {
	var outer certOuter
	if _, err := asn1.Unmarshal(cert.Raw, &outer); err != nil {
		return "", false
	}
	return outer.SigAlg.Algorithm.String(), true
}

func spkiOID(cert *x509.Certificate) (string, bool) {
	var info spki
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &info); err != nil {
		return "", false
	}
	return info.Algorithm.Algorithm.String(), true
}

// ---------- public API ----------

// toComponent converts an X.509 certificate to a CycloneDX component
func CertHitToComponent(ctx context.Context, hit model.CertHit) (cdx.Component, error) {
	cert, path, source := hit.Cert, hit.Location, hit.Source

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
				SignatureAlgorithmRef: ReadSignatureAlgorithmRef(ctx, cert),
				SubjectPublicKeyRef:   ReadSubjectPublicKeyRef(ctx, cert),
				CertificateFormat:     "X.509",
				CertificateExtension:  filepath.Ext(path),
			},
		},
	}

	SetComponentProp(&c, CzertainlyComponentCertificateSourceFormat, source)
	SetComponentProp(&c, CzertainlyComponentCertificateBase64Content, base64.StdEncoding.EncodeToString(cert.Raw))
	AddEvidenceLocation(&c, path)

	return c, nil
}

func ReadSignatureAlgorithmRef(ctx context.Context, cert *x509.Certificate) cdx.BOMReference {
	// Prefer Go’s typed enum first (covers all classic algs cleanly).
	if ref, ok := sigAlgRef[cert.SignatureAlgorithm]; ok {
		return ref
	}

	// Fall back to OID (PQC / unknown to stdlib).
	oid, ok := sigAlgOID(cert)
	if !ok {
		slog.DebugContext(ctx, "Failed to parse signatureAlgorithm OID")
		return refUnknownAlgorithm
	}
	if ref, ok := pqcSigOIDRef[oid]; ok {
		return ref
	}

	slog.DebugContext(ctx, "Unknown signature algorithm OID", "oid", oid)
	return refUnknownAlgorithm
}

func ReadSubjectPublicKeyRef(ctx context.Context, cert *x509.Certificate) cdx.BOMReference {
	// First try concrete key types the stdlib understands.
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

	// Otherwise parse SPKI.algorithm OID (PQC & other non-stdlib types).
	oid, ok := spkiOID(cert)
	if !ok {
		slog.DebugContext(ctx, "Failed to parse SPKI OID")
		return refUnknownKey
	}
	if ref, ok := spkiOIDRef[oid]; ok {
		return ref
	}

	slog.DebugContext(ctx, "Unknown public key algorithm OID", "oid", oid)
	return refUnknownKey
}
