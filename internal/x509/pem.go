package x509

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
)

// pemScanner handles PEM block detection for certificates, PKCS7, and PKCS12
type pemScanner struct{}

// scan finds all certificates in PEM blocks
func (d pemScanner) scan(ctx context.Context, b []byte) []certHit {
	slog.DebugContext(ctx, "Detecting ALL PEM blocks anywhere in the blob (handles leading text)")

	var out []certHit
	rest := b

	for {
		p, r := pem.Decode(rest)
		if p == nil {
			break
		}

		switch p.Type {
		case "CERTIFICATE", "TRUSTED CERTIFICATE":
			if cs, err := x509.ParseCertificates(p.Bytes); err == nil {
				for _, c := range cs {
					if c != nil {
						out = append(out, certHit{Cert: c, Source: "PEM"})
					}
				}
			}
		case "PKCS7", "CMS":
			if cs := parsePKCS7Safe(ctx, p.Bytes, true /*permissive for PEM*/); len(cs) > 0 {
				for _, c := range cs {
					if c != nil {
						out = append(out, certHit{Cert: c, Source: "PKCS7-PEM"})
					}
				}
			}
		case "PKCS12":
			// Only parse PKCS#12 if it actually sniffs as PFX (avoid mis-parsing JKS/BKS as PFX)
			if sniffPKCS12(p.Bytes) {
				certs := pkcs12All(p.Bytes)
				for _, c := range certs {
					if c != nil {
						out = append(out, certHit{Cert: c, Source: "PKCS12"})
					}
				}
			}
		default:
			// ignore keys, CSRs, CRLs, etc.
			slog.DebugContext(ctx, "PEM type ignored by this detector", "type", p.Type)
		}
		rest = r
	}
	return out
}
