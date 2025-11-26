// czertainly package contains constants and helpers for extended properties provided by CZERTAINLY project
package czertainly

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/CZERTAINLY/Seeker/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

const (
	CertificateAuthorityKeyId              = "czertainly:component:certificate:authority_key_id"
	CertificateBase64Content               = "czertainly:component:certificate:base64_content"
	CertificateBasicConstraintsValid       = "czertainly:component:certificate:basic_constraints_valid"
	CertificateCrlDistributionPoints       = "czertainly:component:certificate:crl_distribution_points"
	CertificateExcludedDNSDomains          = "czertainly:component:certificate:excluded_dns_domains"
	CertificateExcludedEmailAddresses      = "czertainly:component:certificate:excluded_email_addresses"
	CertificateExcludedIPRanges            = "czertainly:component:certificate:excluded_ip_ranges"
	CertificateExcludedURIDomains          = "czertainly:component:certificate:excluded_uri_domains"
	CertificateExtendedKeyUsage            = "czertainly:component:certificate:extended_key_usage"
	CertificateExtensionPrefix             = "czertainly:component:certificate:extension:"
	CertificateExtraExtensionPrefix        = "czertainly:component:certificate:extra_extension:"
	CertificateInhibitAnyPolicy            = "czertainly:component:certificate:inhibit_any_policy"
	CertificateInhibitPolicyMapping        = "czertainly:component:certificate:inhibit_policy_mapping"
	CertificateIsCA                        = "czertainly:component:certificate:is_ca"
	CertificateIssuer                      = "czertainly:component:certificate:issuer"
	CertificateIssuingCertificateURLs      = "czertainly:component:certificate:issuing_certificate_urls"
	CertificateKeyUsage                    = "czertainly:component:certificate:key_usage"
	CertificateMaxPathLen                  = "czertainly:component:certificate:max_path_len"
	CertificateOcspServers                 = "czertainly:component:certificate:ocsp_servers"
	CertificatePermittedDNSDomains         = "czertainly:component:certificate:permitted_dns_domains"
	CertificatePermittedDNSDomainsCritical = "czertainly:component:certificate:permitted_dns_domains_critical"
	CertificatePermittedEmailAddresses     = "czertainly:component:certificate:permitted_email_addresses"
	CertificatePermittedIPRanges           = "czertainly:component:certificate:permitted_ip_ranges"
	CertificatePermittedURIDomains         = "czertainly:component:certificate:permitted_uri_domains"
	CertificatePolicies                    = "czertainly:component:certificate:policies"
	CertificatePolicyIdentifiers           = "czertainly:component:certificate:policy_identifiers"
	CertificatePolicyMappings              = "czertainly:component:certificate:policy_mappings"
	CertificateRequireExplicitPolicy       = "czertainly:component:certificate:require_explicit_policy"
	CertificateSourceFormat                = "czertainly:component:certificate:source_format"
	CertificateSubject                     = "czertainly:component:certificate:subject"
	CertificateSubjectAlternativeNames     = "czertainly:component:certificate:subject_alternative_names"
	CertificateSubjectKeyId                = "czertainly:component:certificate:subject_key_id"
	CertificateUnhandledCriticalExtensions = "czertainly:component:certificate:unhandled_critical_extensions"
	CertificateUnknownExtKeyUsage          = "czertainly:component:certificate:unknown_ext_key_usage"
	CertificateVersion                     = "czertainly:component:certificate:version"
	SSHHostKeyFingerprintContent           = "czertainly:component:ssh_hostkey:fingerprint_content"
	SSHHostKeyContent                      = "czertainly:component:ssh_hostkey:content"
	PrivateKeyType                         = "czertainly:component:private_key:type"
	PrivateKeyBase64Content                = "czertainly:component:private_key:base64_content"
	SignatureAlgorithmFamily               = "czertainly:component:algorithm:family"

	// additional PQC data
	AlgorithmPrivateKeySize = "czertainly:component:algorithm:pqc:private_key_size"
	AlgorithmPublicKeySize  = "czertainly:component:algorithm:pqc:public_key_size"
	AlgorithmSignatureSize  = "czertainly:component:algorithm:pqc:signature_size"
)

func CertificateProperties(
	source string,
	cert *x509.Certificate,
	keyUsage []string,
	extKeyUsage []string,
	subjectAltNames []string,
) []cdx.Property {

	var props = make([]cdx.Property, 0, 20)
	props = append(props, cdx.Property{
		Name:  CertificateSourceFormat,
		Value: source,
	})
	props = append(props, cdx.Property{
		Name:  CertificateBase64Content,
		Value: base64.StdEncoding.EncodeToString(cert.Raw),
	})

	if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
		props = append(props, cdx.Property{
			Name:  CertificateMaxPathLen,
			Value: strconv.Itoa(cert.MaxPathLen),
		})
	}
	if len(keyUsage) > 0 {
		props = append(props, cdx.Property{
			Name:  CertificateKeyUsage,
			Value: strings.Join(keyUsage, ","),
		})
	}
	if len(extKeyUsage) > 0 {
		props = append(props, cdx.Property{
			Name:  CertificateExtendedKeyUsage,
			Value: strings.Join(extKeyUsage, ","),
		})
	}

	if len(subjectAltNames) > 0 {
		props = append(props, cdx.Property{
			Name:  CertificateSubjectAlternativeNames,
			Value: strings.Join(subjectAltNames, ","),
		})
	}

	if len(cert.OCSPServer) > 0 {
		props = append(props, cdx.Property{
			Name:  CertificateOcspServers,
			Value: strings.Join(cert.OCSPServer, ","),
		})
	}

	if len(cert.IssuingCertificateURL) > 0 {
		props = append(props, cdx.Property{
			Name:  CertificateIssuingCertificateURLs,
			Value: strings.Join(cert.IssuingCertificateURL, ","),
		})
	}

	if len(cert.CRLDistributionPoints) > 0 {
		props = append(props, cdx.Property{
			Name:  CertificateCrlDistributionPoints,
			Value: strings.Join(cert.CRLDistributionPoints, ","),
		})
	}

	// Version
	props = append(props, cdx.Property{
		Name:  CertificateVersion,
		Value: fmt.Sprintf("%d", cert.Version),
	})

	// Issuer
	if cert.Issuer.String() != "" {
		props = append(props, cdx.Property{
			Name:  CertificateIssuer,
			Value: cert.Issuer.String(),
		})
	}

	// Subject
	if cert.Subject.String() != "" {
		props = append(props, cdx.Property{
			Name:  CertificateSubject,
			Value: cert.Subject.String(),
		})
	}

	// Basic Constraints
	if cert.BasicConstraintsValid {
		props = append(props, cdx.Property{
			Name:  CertificateBasicConstraintsValid,
			Value: "true",
		})
		props = append(props, cdx.Property{
			Name:  CertificateIsCA,
			Value: fmt.Sprintf("%t", cert.IsCA),
		})
	}

	// Subject Key Identifier
	if len(cert.SubjectKeyId) > 0 {
		props = append(props, cdx.Property{
			Name:  CertificateSubjectKeyId,
			Value: hex.EncodeToString(cert.SubjectKeyId),
		})
	}

	// Authority Key Identifier
	if len(cert.AuthorityKeyId) > 0 {
		props = append(props, cdx.Property{
			Name:  CertificateAuthorityKeyId,
			Value: hex.EncodeToString(cert.AuthorityKeyId),
		})
	}

	// Permitted DNS Domains
	if len(cert.PermittedDNSDomains) > 0 {
		props = append(props, cdx.Property{
			Name:  CertificatePermittedDNSDomains,
			Value: strings.Join(cert.PermittedDNSDomains, ","),
		})
		props = append(props, cdx.Property{
			Name:  CertificatePermittedDNSDomainsCritical,
			Value: fmt.Sprintf("%t", cert.PermittedDNSDomainsCritical),
		})
	}

	// Excluded DNS Domains
	if len(cert.ExcludedDNSDomains) > 0 {
		props = append(props, cdx.Property{
			Name:  CertificateExcludedDNSDomains,
			Value: strings.Join(cert.ExcludedDNSDomains, ","),
		})
	}

	// Permitted IP Ranges
	if len(cert.PermittedIPRanges) > 0 {
		var ipRanges []string
		for _, ipNet := range cert.PermittedIPRanges {
			ipRanges = append(ipRanges, ipNet.String())
		}
		props = append(props, cdx.Property{
			Name:  CertificatePermittedIPRanges,
			Value: strings.Join(ipRanges, ","),
		})
	}

	// Excluded IP Ranges
	if len(cert.ExcludedIPRanges) > 0 {
		var ipRanges []string
		for _, ipNet := range cert.ExcludedIPRanges {
			ipRanges = append(ipRanges, ipNet.String())
		}
		props = append(props, cdx.Property{
			Name:  CertificateExcludedIPRanges,
			Value: strings.Join(ipRanges, ","),
		})
	}

	// Permitted Email Addresses
	if len(cert.PermittedEmailAddresses) > 0 {
		props = append(props, cdx.Property{
			Name:  CertificatePermittedEmailAddresses,
			Value: strings.Join(cert.PermittedEmailAddresses, ","),
		})
	}

	// Excluded Email Addresses
	if len(cert.ExcludedEmailAddresses) > 0 {
		props = append(props, cdx.Property{
			Name:  CertificateExcludedEmailAddresses,
			Value: strings.Join(cert.ExcludedEmailAddresses, ","),
		})
	}

	// Permitted URI Domains
	if len(cert.PermittedURIDomains) > 0 {
		props = append(props, cdx.Property{
			Name:  CertificatePermittedURIDomains,
			Value: strings.Join(cert.PermittedURIDomains, ","),
		})
	}

	// Excluded URI Domains
	if len(cert.ExcludedURIDomains) > 0 {
		props = append(props, cdx.Property{
			Name:  CertificateExcludedURIDomains,
			Value: strings.Join(cert.ExcludedURIDomains, ","),
		})
	}

	// Policy Identifiers (legacy field)
	if len(cert.PolicyIdentifiers) > 0 {
		var oids []string
		for _, oid := range cert.PolicyIdentifiers {
			oids = append(oids, oid.String())
		}
		props = append(props, cdx.Property{
			Name:  CertificatePolicyIdentifiers,
			Value: strings.Join(oids, ","),
		})
	}

	// Policies (newer field)
	if len(cert.Policies) > 0 {
		var oids []string
		for _, oid := range cert.Policies {
			oids = append(oids, oid.String())
		}
		props = append(props, cdx.Property{
			Name:  CertificatePolicies,
			Value: strings.Join(oids, ","),
		})
	}

	// Policy Constraints - InhibitAnyPolicy
	if cert.InhibitAnyPolicyZero || cert.InhibitAnyPolicy > 0 {
		props = append(props, cdx.Property{
			Name:  CertificateInhibitAnyPolicy,
			Value: fmt.Sprintf("%d", cert.InhibitAnyPolicy),
		})
	}

	// Policy Constraints - InhibitPolicyMapping
	if cert.InhibitPolicyMappingZero || cert.InhibitPolicyMapping > 0 {
		props = append(props, cdx.Property{
			Name:  CertificateInhibitPolicyMapping,
			Value: fmt.Sprintf("%d", cert.InhibitPolicyMapping),
		})
	}

	// Policy Constraints - RequireExplicitPolicy
	if cert.RequireExplicitPolicyZero || cert.RequireExplicitPolicy > 0 {
		props = append(props, cdx.Property{
			Name:  CertificateRequireExplicitPolicy,
			Value: fmt.Sprintf("%d", cert.RequireExplicitPolicy),
		})
	}

	// Policy Mappings
	if len(cert.PolicyMappings) > 0 {
		var mappings []string
		for _, pm := range cert.PolicyMappings {
			mappings = append(mappings, fmt.Sprintf("%s->%s", pm.IssuerDomainPolicy.String(), pm.SubjectDomainPolicy.String()))
		}
		props = append(props, cdx.Property{
			Name:  CertificatePolicyMappings,
			Value: strings.Join(mappings, ","),
		})
	}

	// Unhandled Critical Extensions
	if len(cert.UnhandledCriticalExtensions) > 0 {
		var oids []string
		for _, oid := range cert.UnhandledCriticalExtensions {
			oids = append(oids, oid.String())
		}
		props = append(props, cdx.Property{
			Name:  CertificateUnhandledCriticalExtensions,
			Value: strings.Join(oids, ","),
		})
	}

	// Unknown Extended Key Usages
	if len(cert.UnknownExtKeyUsage) > 0 {
		var oids []string
		for _, oid := range cert.UnknownExtKeyUsage {
			oids = append(oids, oid.String())
		}
		props = append(props, cdx.Property{
			Name:  CertificateUnknownExtKeyUsage,
			Value: strings.Join(oids, ","),
		})
	}

	// Extensions (raw extensions)
	if len(cert.Extensions) > 0 {
		for _, ext := range cert.Extensions {
			props = append(props, cdx.Property{
				Name:  fmt.Sprintf("%s%s", CertificateExtensionPrefix, ext.Id.String()),
				Value: fmt.Sprintf("critical=%t,value=%s", ext.Critical, hex.EncodeToString(ext.Value)),
			})
		}
	}

	// Extra Extensions
	if len(cert.ExtraExtensions) > 0 {
		for _, ext := range cert.ExtraExtensions {
			props = append(props, cdx.Property{
				Name:  fmt.Sprintf("%s%s", CertificateExtraExtensionPrefix, ext.Id.String()),
				Value: fmt.Sprintf("critical=%t,value=%s", ext.Critical, hex.EncodeToString(ext.Value)),
			})
		}
	}

	return props
}

func SSHHostKeyProperties(props []cdx.Property, key model.SSHHostKey) []cdx.Property {
	p1 := cdx.Property{
		Name:  SSHHostKeyContent,
		Value: key.Key,
	}
	p2 := cdx.Property{
		Name:  SSHHostKeyFingerprintContent,
		Value: key.Fingerprint,
	}
	return append(props, []cdx.Property{p1, p2}...)
}
