package bom_test

import (
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/bom"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestBuilder(t *testing.T) {
	t.Parallel()

	b := bom.NewBuilder().
		AppendAuthors(cdx.OrganizationalContact{
			BOMRef: "",
			Name:   "test-author",
			Email:  "test.author@example.net",
			Phone:  "+1 555 555 5555",
		}).
		AppendComponents(cdx.Component{
			BOMRef:       "",
			MIMEType:     "application/x-pem-file",
			Type:         "cryptographic-asset",
			Supplier:     &cdx.OrganizationalEntity{},
			Manufacturer: &cdx.OrganizationalEntity{},
			Author:       "",
			Authors:      &[]cdx.OrganizationalContact{},
			Publisher:    "",
			Group:        "",
			Name:         "cert.pem",
			Version:      "",
			Description:  "",
			Scope:        "",
			Hashes: &[]cdx.Hash{
				{
					Algorithm: "sha256",
					Value:     "??",
				},
			},
			Licenses:           &cdx.Licenses{},
			Copyright:          "",
			CPE:                "",
			PackageURL:         "",
			OmniborID:          &[]string{},
			SWHID:              &[]string{},
			SWID:               &cdx.SWID{},
			Modified:           new(bool),
			Pedigree:           &cdx.Pedigree{},
			ExternalReferences: &[]cdx.ExternalReference{},
			Properties:         &[]cdx.Property{},
			Components:         &[]cdx.Component{},
			Evidence:           &cdx.Evidence{},
			ReleaseNotes:       &cdx.ReleaseNotes{},
			ModelCard:          &cdx.MLModelCard{},
			Data:               &[]cdx.ComponentData{},
			CryptoProperties: &cdx.CryptoProperties{
				AssetType:           "certificate",
				AlgorithmProperties: &cdx.CryptoAlgorithmProperties{},
				CertificateProperties: &cdx.CertificateProperties{
					SubjectName:           "CN=CommonNameOrHostname",
					IssuerName:            "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName",
					NotValidBefore:        "",
					NotValidAfter:         "",
					SignatureAlgorithmRef: "crypto/algorithm/sha-512-rsa@1.2.840.113549.1.1.13",
					SubjectPublicKeyRef:   "",
					CertificateFormat:     "X.509",
					CertificateExtension:  "crt",
				},
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{},
				ProtocolProperties:              &cdx.CryptoProtocolProperties{},
				OID:                             "",
			},
		}).AppendProperties(cdx.Property{
		Name:  "property1",
		Value: "value1",
	}).
		AppendDependencies(cdx.Dependency{
			Ref: "ref",
			Dependencies: &[]string{
				"dep-1",
				"dep-2",
			},
		})

	err := b.AsJSON(t.Output())
	require.NoError(t, err)
}
