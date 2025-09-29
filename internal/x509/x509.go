package x509

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"log/slog"

	"github.com/CZERTAINLY/Seeker/internal/model"

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

// detector interface for certificate detection
type detector interface {
	detect(ctx context.Context, b []byte) []certHit
}

func findAllCerts(ctx context.Context, b []byte) []certHit {
	seen := make(map[[32]byte]struct{})
	add := func(hits []certHit, out *[]certHit) {
		for _, h := range hits {
			if h.Cert == nil {
				continue
			}
			fp := sha256.Sum256(h.Cert.Raw)
			if _, dup := seen[fp]; dup {
				continue
			}
			seen[fp] = struct{}{}
			*out = append(*out, h)
		}
	}

	out := make([]certHit, 0, 4)

	// Initialize all detectors
	detectors := []detector{
		pemDetector{},    // 1) PEM blocks (handles certificates, PKCS7, PKCS12 in PEM)
		jksDetector{},    // 2) JKS / JCEKS (Java keystores)
		pkcs12Detector{}, // 3) PKCS#12 (PFX)
		derDetector{},    // 4) Raw DER (single/concatenated certs, or DER-encoded PKCS#7)
		zipDetector{},    // 5) ZIP/JAR/APK META-INF
	}

	// Run all detectors
	for _, d := range detectors {
		hits := d.detect(ctx, b)
		add(hits, &out)
	}

	return out
}


