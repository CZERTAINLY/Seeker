package x509

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"log/slog"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
)

// jksDetector handles JKS/JCEKS keystore detection
type jksDetector struct{}

// detect finds certificates in JKS/JCEKS keystores
func (d jksDetector) detect(ctx context.Context, b []byte) []certHit {
	slog.DebugContext(ctx, "Detecting JKS / JCEKS (Java keystores)")
	
	var out []certHit
	
	if certs, kind := jksAll(b); len(certs) > 0 && kind != "" {
		for _, c := range certs {
			if c != nil {
				out = append(out, certHit{Cert: c, Source: kind})
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