package czertainly_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"net"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops/czertainly"
	"github.com/CZERTAINLY/Seeker/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestCertificateProperties(t *testing.T) {
	_, ipNet1, err := net.ParseCIDR("192.0.2.0/24")
	require.NoError(t, err)
	_, ipNet2, err := net.ParseCIDR("198.51.100.0/24")
	require.NoError(t, err)

	cert := &x509.Certificate{
		Raw:                         []byte("rawderp"),
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		OCSPServer:                  []string{"http://ocsp.example"},
		IssuingCertificateURL:       []string{"http://issuing.example"},
		CRLDistributionPoints:       []string{"http://crl.example"},
		Version:                     3,
		Issuer:                      pkix.Name{CommonName: "Issuer CN"},
		Subject:                     pkix.Name{CommonName: "Subject CN"},
		BasicConstraintsValid:       true,
		IsCA:                        true,
		SubjectKeyId:                []byte{0x01, 0x02},
		AuthorityKeyId:              []byte{0x0a, 0x0b},
		PermittedDNSDomains:         []string{"allowed.example"},
		PermittedDNSDomainsCritical: true,
		ExcludedDNSDomains:          []string{"excluded.example"},
		PermittedIPRanges:           []*net.IPNet{ipNet1},
		ExcludedIPRanges:            []*net.IPNet{ipNet2},
		PermittedEmailAddresses:     []string{"allowed@example.com"},
		ExcludedEmailAddresses:      []string{"excluded@example.com"},
		PermittedURIDomains:         []string{"allowed.uri"},
		ExcludedURIDomains:          []string{"excluded.uri"},
		PolicyIdentifiers:           []asn1.ObjectIdentifier{{1, 2, 3}},
		Policies:                    nil,
		InhibitAnyPolicyZero:        true,
		InhibitAnyPolicy:            0,
		InhibitPolicyMappingZero:    true,
		InhibitPolicyMapping:        0,
		RequireExplicitPolicyZero:   true,
		RequireExplicitPolicy:       0,
		PolicyMappings:              nil,
		UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{2, 5, 29, 15}},
		UnknownExtKeyUsage:          []asn1.ObjectIdentifier{{1, 2, 840}},
		Extensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{1, 2, 3},
				Critical: true,
				Value:    []byte{0x0a},
			},
		},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{1, 2, 4},
				Critical: false,
				Value:    []byte{0x0b},
			},
		},
	}

	keyUsage := []string{"digitalSignature", "keyEncipherment"}
	extKeyUsage := []string{"clientAuth", "serverAuth"}
	subjectAltNames := []string{"alt1.example", "alt2.example"}

	props := czertainly.CertificateProperties("PEM", cert, keyUsage, extKeyUsage, subjectAltNames)

	// build map of properties for assertions
	values := make(map[string]string, len(props))
	for _, p := range props {
		values[p.Name] = p.Value
	}

	require.Equal(t, "PEM", values[czertainly.CertificateSourceFormat])
	require.Equal(t, base64.StdEncoding.EncodeToString(cert.Raw), values[czertainly.CertificateBase64Content])
	require.Equal(t, "0", values[czertainly.CertificateMaxPathLen]) // MaxPathLenZero true -> should include "0"
	require.Equal(t, "digitalSignature,keyEncipherment", values[czertainly.CertificateKeyUsage])
	require.Equal(t, "clientAuth,serverAuth", values[czertainly.CertificateExtendedKeyUsage])
	require.Equal(t, "alt1.example,alt2.example", values[czertainly.CertificateSubjectAlternativeNames])
	require.Equal(t, "http://ocsp.example", values[czertainly.CertificateOcspServers])
	require.Equal(t, "http://issuing.example", values[czertainly.CertificateIssuingCertificateURLs])
	require.Equal(t, "http://crl.example", values[czertainly.CertificateCrlDistributionPoints])
	require.Equal(t, "3", values[czertainly.CertificateVersion])
	require.Contains(t, values[czertainly.CertificateIssuer], "Issuer CN")
	require.Contains(t, values[czertainly.CertificateSubject], "Subject CN")
	require.Equal(t, "true", values[czertainly.CertificateBasicConstraintsValid])
	require.Equal(t, "true", values[czertainly.CertificateIsCA])
	require.Equal(t, hex.EncodeToString(cert.SubjectKeyId), values[czertainly.CertificateSubjectKeyId])
	require.Equal(t, hex.EncodeToString(cert.AuthorityKeyId), values[czertainly.CertificateAuthorityKeyId])
	require.Equal(t, "allowed.example", values[czertainly.CertificatePermittedDNSDomains])
	require.Equal(t, "true", values[czertainly.CertificatePermittedDNSDomainsCritical])
	require.Equal(t, "excluded.example", values[czertainly.CertificateExcludedDNSDomains])
	require.Equal(t, ipNet1.String(), values[czertainly.CertificatePermittedIPRanges])
	require.Equal(t, ipNet2.String(), values[czertainly.CertificateExcludedIPRanges])
	require.Equal(t, "allowed@example.com", values[czertainly.CertificatePermittedEmailAddresses])
	require.Equal(t, "excluded@example.com", values[czertainly.CertificateExcludedEmailAddresses])
	require.Equal(t, "allowed.uri", values[czertainly.CertificatePermittedURIDomains])
	require.Equal(t, "excluded.uri", values[czertainly.CertificateExcludedURIDomains])
	require.Equal(t, "1.2.3", values[czertainly.CertificatePolicyIdentifiers])
	require.Equal(t, "", values[czertainly.CertificatePolicies])
	require.Equal(t, "0", values[czertainly.CertificateInhibitAnyPolicy])
	require.Equal(t, "0", values[czertainly.CertificateInhibitPolicyMapping])
	require.Equal(t, "0", values[czertainly.CertificateRequireExplicitPolicy])
	require.Equal(t, "", values[czertainly.CertificatePolicyMappings])
	require.Equal(t, "2.5.29.15", values[czertainly.CertificateUnhandledCriticalExtensions])
	require.Equal(t, "1.2.840", values[czertainly.CertificateUnknownExtKeyUsage])
	// extensions
	require.Equal(t, "critical=true,value=0a", values[czertainly.CertificateExtensionPrefix+"1.2.3"])
	require.Equal(t, "critical=false,value=0b", values[czertainly.CertificateExtraExtensionPrefix+"1.2.4"])
}

func TestSSHHostKeyProperties(t *testing.T) {
	initial := []cdx.Property{
		{Name: "initial", Value: "v"},
	}
	key := model.SSHHostKey{
		Key:         "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC",
		Fingerprint: "aa:bb:cc:dd",
	}

	props := czertainly.SSHHostKeyProperties(initial, key)
	require.Len(t, props, 3)
	// initial preserved
	require.Equal(t, "initial", props[0].Name)
	require.Equal(t, "v", props[0].Value)
	// appended properties
	require.Equal(t, czertainly.SSHHostKeyContent, props[1].Name)
	require.Equal(t, key.Key, props[1].Value)
	require.Equal(t, czertainly.SSHHostKeyFingerprintContent, props[2].Name)
	require.Equal(t, key.Fingerprint, props[2].Value)
}
