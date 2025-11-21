// czertainly package contains constants and helpers for extended properties provided by CZERTAINLY project
package czertainly

import (
	"crypto/x509"
	"encoding/base64"

	"github.com/CZERTAINLY/Seeker/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

const (
	ComponentCertificateSourceFormat      = "czertainly:component:certificate:source_format"
	ComponentCertificateBase64Content     = "czertainly:component:certificate:base64_content"
	ComponentSSHHostKeyFingerprintContent = "czertainly:component:ssh_hostkey:fingerprint_content"
	ComponentSSHHostKeyContent            = "czertainly:component:ssh_hostkey:content"
	PrivateKeyType                        = "czertainly:component:private_key:type"
	PrivateKeyBase64Content               = "czertainly:component:private_key:base64_content"
)

func CertificateProperties(props []cdx.Property, source string, cert *x509.Certificate) []cdx.Property {
	if cert == nil {
		return props
	}
	p1 := cdx.Property{
		Name:  ComponentCertificateSourceFormat,
		Value: source,
	}
	p2 := cdx.Property{
		Name:  ComponentCertificateBase64Content,
		Value: base64.StdEncoding.EncodeToString(cert.Raw),
	}
	return append(props, []cdx.Property{p1, p2}...)
}

func SSHHostKeyProperties(props []cdx.Property, key model.SSHHostKey) []cdx.Property {
	p1 := cdx.Property{
		Name:  ComponentSSHHostKeyContent,
		Value: key.Key,
	}
	p2 := cdx.Property{
		Name:  ComponentSSHHostKeyFingerprintContent,
		Value: key.Fingerprint,
	}
	return append(props, []cdx.Property{p1, p2}...)
}
