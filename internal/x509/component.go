package x509

import (
	"crypto/dsa" //nolint:staticcheck // seeker is going to recognize even obsoleted crypto
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

// toComponent converts an X.509 certificate to a CycloneDX component
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