package x509

import (
	"context"
	"crypto/x509"
	"log/slog"
)

// derDetector handles raw DER certificate detection
type derDetector struct{}

// detect finds certificates in raw DER format (single or concatenated)
func (d derDetector) detect(ctx context.Context, b []byte) []certHit {
	slog.DebugContext(ctx, "Detecting Raw DER: single/concatenated certs, or DER-encoded PKCS#7")
	
	var out []certHit
	
	// Try to parse as raw DER certificates first
	if cs, err := x509.ParseCertificates(b); err == nil {
		for _, c := range cs {
			if c != nil {
				out = append(out, certHit{Cert: c, Source: "DER"})
			}
		}
		return out
	}
	
	// If that fails, check if it's DER PKCS#7
	if sniffPKCS7DER(b) {
		if cs := parsePKCS7Safe(ctx, b, false /*strict*/); len(cs) > 0 {
			for _, c := range cs {
				if c != nil {
					out = append(out, certHit{Cert: c, Source: "PKCS7-DER"})
				}
			}
		}
	}
	return out
}