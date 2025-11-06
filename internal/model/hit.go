package model

import "crypto/x509"

type CertHit struct {
	Cert     *x509.Certificate
	Source   string // e.g., "PEM", "DER", "PKCS7-PEM", "PKCS7-DER", "PKCS12", "JKS", "JCEKS", "ZIP/<subsource>", "NMAP"
	Location string // path or port or image name or any similar identifier
}
