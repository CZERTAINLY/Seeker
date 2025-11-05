package model

import "crypto/x509"

// PEMHit contains data from known sources of pem certificates _before_ they're parsed
// an example is nmap output
type PEMHit struct {
	Raw      []byte // raw data for a detectors to parse
	Location string // path or port or image name or any similar identifier
	Source   string // how it was obtained, eg nmap
}

type CertHit struct {
	Cert     *x509.Certificate
	Source   string // e.g., "PEM", "DER", "PKCS7-PEM", "PKCS7-DER", "PKCS12", "JKS", "JCEKS", "ZIP/<subsource>"
	Location string // path or port or image name or any similar identifier
}
