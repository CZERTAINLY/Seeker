package x509

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/CZERTAINLY/Seeker/internal/model"
)

// Detector tries to parse the X509 certificate and return a proper detection object
type Detector struct {
}

func (d Detector) Detect(b []byte, path string) ([]model.Detection, error) {
	cert, _ := isx509(b)
	if cert != nil {
		return []model.Detection{{
			Path: path,
			Typ:  "X509",
		}}, nil
	}
	return nil, model.ErrNoMatch
}

func isx509(b []byte) (*x509.Certificate, error) {
	// 1. Try PEM decoding first
	if p, _ := pem.Decode(b); p != nil {
		if p.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block is not a certificate")
		}
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PEM cert: %w", err)
		}
		return cert, nil
	}

	// 2. If not PEM, try raw DER
	cert, err := x509.ParseCertificate(b)
	if err == nil {
		return cert, nil
	}

	// 3. Could also be a chain (PKCS#7/PKCS#12 are not in stdlib)
	certs, err2 := x509.ParseCertificates(b)
	if err2 == nil && len(certs) > 0 {
		return certs[0], nil // return the first one
	}

	return nil, errors.New("not an X.509 certificate")
}
