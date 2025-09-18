package x509

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/dsa" //nolint:staticcheck // seeker is going to recognize even obsoleted crypto
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ---- internal type to carry source/format label ----

type certHit struct {
	Cert   *x509.Certificate
	Source string // e.g., "PEM", "DER", "PKCS7-PEM", "PKCS7-DER", "PKCS12", "JKS", "JCEKS", "ZIP/<subsource>"
}

// Detector tries to parse the X509 certificate(s) and return a proper detection object
type Detector struct{}

func (d Detector) Detect(ctx context.Context, b []byte, path string) ([]model.Detection, error) {
	hits := findAllCerts(ctx, b)
	if len(hits) == 0 {
		return nil, model.ErrNoMatch
	}

	components := make([]cdx.Component, 0, len(hits))
	for _, h := range hits {
		component, err := toComponent(h.Cert, path, h.Source)
		if err != nil {
			return nil, err
		}
		components = append(components, component)
	}

	return []model.Detection{{
		Path:       path,
		Components: components,
	}}, nil
}

func (d Detector) LogAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("detector", "x509"),
	}
}

// -------- Certificate extraction (multi-source) --------

func findAllCerts(ctx context.Context, b []byte) []certHit {
	seen := make(map[[32]byte]struct{})
	add := func(cs []*x509.Certificate, source string, out *[]certHit) {
		for _, c := range cs {
			if c == nil {
				continue
			}
			fp := sha256.Sum256(c.Raw)
			if _, dup := seen[fp]; dup {
				continue
			}
			seen[fp] = struct{}{}
			*out = append(*out, certHit{Cert: c, Source: source})
		}
	}

	out := make([]certHit, 0, 4)

	// 1) Detecting ALL PEM blocks anywhere in the blob (handles leading text)
	slog.DebugContext(ctx, "Detecting ALL PEM blocks anywhere in the blob (handles leading text)")
	rest := b
	for {
		p, r := pem.Decode(rest)
		if p == nil {
			break
		}
		switch p.Type {
		case "CERTIFICATE", "TRUSTED CERTIFICATE":
			if cs, err := x509.ParseCertificates(p.Bytes); err == nil {
				add(cs, "PEM", &out)
			}
		case "PKCS7", "CMS":
			if cs := parsePKCS7(p.Bytes); len(cs) > 0 {
				add(cs, "PKCS7-PEM", &out)
			}
		case "PKCS12":
			// Only parse PKCS#12 if it actually sniffs as PFX (avoid mis-parsing JKS/BKS as PFX)
			if sniffPKCS12(p.Bytes) {
				add(pkcs12All(p.Bytes), "PKCS12", &out)
			}
		default:
			// ignore keys, CSRs, CRLs, etc.
		}
		rest = r
	}

	// 2) JKS / JCEKS (Java keystores) — check magic+version before loading
	slog.DebugContext(ctx, "Detecting JKS / JCEKS (Java keystores)")
	if certs, kind := jksAll(b); len(certs) > 0 && kind != "" {
		add(certs, kind, &out)
	}

	// 3) PKCS#12 (PFX) — try only if it sniffs as PFX
	slog.DebugContext(ctx, "Detecting PKCS#12 (PFX)")
	if sniffPKCS12(b) {
		add(pkcs12All(b), "PKCS12", &out)
	}

	// 4) Raw DER: single/concatenated certs, or DER-encoded PKCS#7
	slog.DebugContext(ctx, "Detecting Raw DER: single/concatenated certs, or DER-encoded PKCS#7")
	if cs, err := x509.ParseCertificates(b); err == nil {
		add(cs, "DER", &out)
	} else {
		// DER PKCS#7?
		if cs := parsePKCS7(b); len(cs) > 0 {
			add(cs, "PKCS7-DER", &out)
		}
	}

	// 5) ZIP/JAR/APK META-INF (common in signed Java/Android artifacts)
	slog.DebugContext(ctx, "Detecting ZIP/JAR/APK META-INF")
	if bytes.HasPrefix(b, []byte("PK\x03\x04")) {
		for _, h := range scanZIPForCerts(ctx, b) {
			add([]*x509.Certificate{h.Cert}, "ZIP/"+h.Source, &out)
		}
	}

	return out
}

func parsePKCS7(_ []byte) []*x509.Certificate {
	//FIXME: code used stepcms "github.com/smallstep/pkcs7"
	// however it's parse method fails on a lot of common files including
	// Go source code or JSON. The effect is that Parse allocated tons of GBs of memory
	// and never finish.
	// For this reason this is no-op, until we'll find a safe way how to parse PKCS7.
	return nil
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

// --- JKS/JCEKS support ---

const (
	jksMagic   uint32 = 0xFEEDFEED
	jceksMagic uint32 = 0xCECECECE
)

// sniffJKS returns (true, "JKS"|"JCEKS") if bytes look like a JKS/JCEKS keystore.
// It also validates the version (1 or 2) to reduce false positives.
func sniffJKS(b []byte) (bool, string) {
	if len(b) < 8 {
		return false, ""
	}
	magic := binary.BigEndian.Uint32(b[0:4])
	if magic != jksMagic && magic != jceksMagic {
		return false, ""
	}
	version := binary.BigEndian.Uint32(b[4:8])
	if version != 1 && version != 2 {
		return false, ""
	}
	if magic == jksMagic {
		return true, "JKS"
	}
	return true, "JCEKS"
}

var jksPasswords = []string{"changeit", ""} // typical defaults; adjust as needed

func jksAll(b []byte) ([]*x509.Certificate, string) {
	ok, kind := sniffJKS(b)
	if !ok {
		return nil, ""
	}

	var out []*x509.Certificate
	for _, pw := range jksPasswords {
		ks := keystore.New()
		if err := ks.Load(bytes.NewReader(b), []byte(pw)); err != nil {
			continue
		}

		aliases := ks.Aliases()
		for _, alias := range aliases {
			// 1) TrustedCertificateEntry
			if tce, err := ks.GetTrustedCertificateEntry(alias); err == nil {
				if c, err := x509.ParseCertificate(tce.Certificate.Content); err == nil {
					out = append(out, c)
				}
			}
			// 2) PrivateKeyEntry -> includes certificate chain
			if pke, err := ks.GetPrivateKeyEntry(alias, []byte(pw)); err == nil {
				for _, kc := range pke.CertificateChain {
					if c, err := x509.ParseCertificate(kc.Content); err == nil {
						out = append(out, c)
					}
				}
			}
		}

		if len(out) > 0 {
			break
		}
	}
	return out, kind
}

func scanZIPForCerts(ctx context.Context, b []byte) []certHit {
	var out []certHit
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil
	}
	for _, f := range zr.File {
		name := strings.ToUpper(f.Name)
		if !strings.HasPrefix(name, "META-INF/") {
			continue
		}
		// Typical: CERT.RSA, *.RSA, *.DSA, *.EC, *.PK7
		//nolint:staticcheck // seeker is going to recognize even obsoleted crypto
		if !(strings.HasSuffix(name, ".RSA") || strings.HasSuffix(name, ".DSA") ||
			strings.HasSuffix(name, ".EC") || strings.HasSuffix(name, ".PK7") ||
			name == "META-INF/CERT.RSA") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(rc)
		_ = rc.Close()

		// Recursively analyze entry contents (they're usually PKCS#7)
		sub := findAllCerts(ctx, data)
		for _, h := range sub {
			out = append(out, certHit{Cert: h.Cert, Source: "ZIP/" + h.Source})
		}
	}
	return out
}

// -------- Optional sanity (kept for reference, not used by default) --------

//func saneCert(cert *x509.Certificate) (bool, error) { // optional policy filter
//	if cert.SerialNumber == nil || cert.SerialNumber.Sign() == 0 {
//		return false, errors.New("bad serial")
//	}
//	if !cert.NotBefore.Before(cert.NotAfter) {
//		return false, errors.New("bad validity window")
//	}
//	span := cert.NotAfter.Sub(cert.NotBefore)
//	if span > 24*time.Hour*365*30 { // >30y validity is suspicious
//		return false, errors.New("implausible validity")
//	}
//	switch pk := cert.PublicKey.(type) {
//	case *rsa.PublicKey:
//		if pk.N.BitLen() < 1024 {
//			return false, errors.New("RSA too small")
//		}
//	case *ecdsa.PublicKey:
//		switch pk.Params().BitSize {
//		case 256, 384, 521:
//		default:
//			return false, fmt.Errorf("unsupported EC size %d", pk.Params().BitSize)
//		}
//	case ed25519.PublicKey:
//		// ok
//	case *dsa.PublicKey:
//		if pk.P.BitLen() < 1024 {
//			return false, errors.New("DSA too small")
//		}
//	default:
//		return false, fmt.Errorf("unsupported public key type: %T", cert.PublicKey)
//	}
//	return true, nil
//}

// -------- Component building --------

func toComponent(cert *x509.Certificate, path string, source string) (cdx.Component, error) {
	subjectPublicKeyRef, err := readSubjectPublicKeyRef(cert)
	if err != nil {
		return cdx.Component{}, err
	}

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
				SignatureAlgorithmRef: readSignatureAlgorithmRef(cert),
				SubjectPublicKeyRef:   subjectPublicKeyRef,
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

func readSignatureAlgorithmRef(cert *x509.Certificate) cdx.BOMReference {
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
	case x509.SHA256WithRSAPSS:
		return "crypto/algorithm/sha-256-rsassa-pss@1.2.840.113549.1.1.10"
	case x509.SHA384WithRSAPSS:
		return "crypto/algorithm/sha-384-rsassa-pss@1.2.840.113549.1.1.10"
	case x509.SHA512WithRSAPSS:
		return "crypto/algorithm/sha-512-rsassa-pss@1.2.840.113549.1.1.10"
	case x509.PureEd25519:
		return "crypto/algorithm/ed25519@1.3.101.112"
	default:
		return ""
	}
}

func readSubjectPublicKeyRef(cert *x509.Certificate) (cdx.BOMReference, error) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return cdx.BOMReference(fmt.Sprintf("crypto/key/rsa-%d@1.2.840.113549.1.1.1", pub.N.BitLen())), nil
	case *ecdsa.PublicKey:
		bitSize := pub.Params().BitSize
		// Curve OIDs
		switch bitSize {
		case 256:
			return "crypto/key/ecdsa-p256@1.2.840.10045.3.1.7", nil
		case 384:
			return "crypto/key/ecdsa-p384@1.3.132.0.34", nil
		case 521:
			return "crypto/key/ecdsa-p521@1.3.132.0.35", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA key size: %d", bitSize)
		}
	case ed25519.PublicKey:
		return "crypto/key/ed25519-256@1.3.101.112", nil
	case *dsa.PublicKey:
		return cdx.BOMReference(fmt.Sprintf("crypto/key/dsa-%d@1.2.840.10040.4.1", pub.P.BitLen())), nil
	default:
		return "", fmt.Errorf("unsupported public key type: %T", cert.PublicKey)
	}
}
