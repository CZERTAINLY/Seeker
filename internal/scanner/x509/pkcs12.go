package x509

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"log/slog"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// pkcs12Scanner handles PKCS#12/PFX detection
type pkcs12Scanner struct{}

// scan finds certificates in PKCS#12/PFX format
func (d pkcs12Scanner) scan(ctx context.Context, b []byte) []certHit {
	slog.DebugContext(ctx, "Detecting PKCS#12 (PFX)")

	var out []certHit

	// Only try if it sniffs as PFX
	if sniffPKCS12(b) {
		certs := pkcs12All(b)
		for _, c := range certs {
			if c != nil {
				out = append(out, certHit{Cert: c, Source: "PKCS12"})
			}
		}
	}
	slog.DebugContext(ctx, "Result of PKCS#12 (PFX) detection", "hits", len(out))

	return out
}

// ParsePKCS12 extracts X.509 certificates from DER-encoded PKCS#12/PFX data.
// It first validates the input has a valid PKCS#12 structure, then attempts to
// decode certificates using common passwords (changeit, empty, password).
// Returns nil if the data is not valid PKCS#12 or no certificates could be extracted.
// The function tries both trust-store format (certificates only) and full chain
// format (private key + certificates), returning the first successful decode.
// Note: Input must be DER-encoded; PEM-wrapped PKCS#12 is not supported.
func ParsePKCS12(ctx context.Context, b []byte) []*x509.Certificate {
	if !sniffPKCS12(b) {
		return nil
	}
	return pkcs12All(b)

}

// --- Strict PKCS#12 sniff ---
// Validates top-level PFX structure: SEQUENCE { version INTEGER, authSafe ContentInfo (...id-data or id-signedData...) , ... }
func sniffPKCS12(b []byte) bool {
	var top asn1.RawValue
	if _, err := asn1.Unmarshal(b, &top); err != nil {
		return false
	}
	if top.Class != asn1.ClassUniversal || top.Tag != asn1.TagSequence || !top.IsCompound {
		return false
	}
	payload := top.Bytes
	// version INTEGER
	var ver int
	rest, err := asn1.Unmarshal(payload, &ver)
	if err != nil || ver < 0 || ver > 10 { // typical PFX version is 3
		return false
	}
	// ContentInfo: SEQUENCE { contentType OID, [0] EXPLICIT ... OPTIONAL }
	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
	}
	var ci contentInfo
	if _, err := asn1.Unmarshal(rest, &ci); err != nil {
		return false
	}
	// contentType must be id-data (1.2.840.113549.1.7.1) or id-signedData (1.2.840.113549.1.7.2)
	idData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	idSignedData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	return ci.ContentType.Equal(idData) || ci.ContentType.Equal(idSignedData)
}

var pkcs12Passwords = []string{"changeit", "", "password"} // tweak as needed

// Robust PKCS#12: trust store first, then key+chain, then PEM fallback.
func pkcs12All(b []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for _, pw := range pkcs12Passwords {
		// 1) Trust-store (certs only; e.g., Java truststore exports)
		if certs, err := pkcs12.DecodeTrustStore(b, pw); err == nil && len(certs) > 0 {
			out = append(out, certs...)
			return out
		}
		// 2) Full chain (leaf + intermediates) if present
		if _, leaf, cas, err := pkcs12.DecodeChain(b, pw); err == nil {
			if leaf != nil {
				out = append(out, leaf)
			}
			if len(cas) > 0 {
				out = append(out, cas...)
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return out
}
