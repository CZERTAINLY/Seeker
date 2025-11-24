package cdxprops_test

import (
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/stretchr/testify/require"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

const testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALqbHeRLCyOdykC5SDLqI49ArYGYG1mqecwBP6qb/tPPf3FJAAQB
nmlss7TBypQbISlfWrPDJUvAGYa2sVrCWicCAwEAAQJAYaTrFT8/KpvhgwOnqPlk
NmB0/psxUO9R38bWbHFv3lQgELgqTby8IER4aRRaCGu0qU/WVSoS5WyKrOEptsbq
AQIhAOR79yKC1TMfGhgRG2RWBRc0QkJa+zp5tO5+u/Gb15WBAiEA0UYB1XrCixaV
H6eJGLX4bKiSVCkUuK3p7Pn6RRXuG0cCIHPyp8i6yMxAX0COx3KRwrE6IIWcA1Zk
lABDpadD2I1BAiAUdH1khVQj1U+lgp6MZnJGdKSg1jKRKEvHDTkcznajDwIgS0xX
1JzwMdPOHHxeDZJj8HBpapEIJrb3X1iPlMNmZQA=
-----END RSA PRIVATE KEY-----`

func TestLeakToComponent(t *testing.T) {
	var startLine = 42
	tests := []struct {
		scenario string
		given    model.Leak
		then     cdx.Component
		ignored  bool
	}{
		{
			scenario: "private key should be ignored",
			given: model.Leak{
				RuleID:    "private-key",
				File:      "privKey.pem",
				StartLine: startLine,
				Content:   string(testPrivateKey),
			},
			ignored: true,
		},
		{
			scenario: "jwt token detection",
			given: model.Leak{
				RuleID:      "jwt-token",
				Description: "Found JWT token",
				File:        "/path/to/file",
				StartLine:   42,
			},
			then: cdx.Component{
				Name:        "jwt-token",
				Description: "Found JWT token",
				Type:        cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
					RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
						Type: cdx.RelatedCryptoMaterialTypeToken,
					},
				},
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{
							Location: "/path/to/file",
							Line:     intPtr(42),
						},
					},
				},
			},
		},
		{
			scenario: "api key detection",
			given: model.Leak{
				RuleID:      "api-key",
				Description: "Found API key",
				File:        "/path/to/file",
				StartLine:   10,
			},
			then: cdx.Component{
				Name:        "api-key",
				Description: "Found API key",
				Type:        cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
					RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
						Type: cdx.RelatedCryptoMaterialTypeKey,
					},
				},
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{
							Location: "/path/to/file",
							Line:     intPtr(10),
						},
					},
				},
			},
		},
		{
			scenario: "password detection",
			given: model.Leak{
				RuleID:      "password-leak",
				Description: "Found password",
				File:        "/path/to/file",
				StartLine:   15,
			},
			then: cdx.Component{
				Name:        "password-leak",
				Description: "Found password",
				Type:        cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
					RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
						Type: cdx.RelatedCryptoMaterialTypePassword,
					},
				},
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{
							Location: "/path/to/file",
							Line:     intPtr(15),
						},
					},
				},
			},
		},
		{
			scenario: "unknown type detection",
			given: model.Leak{
				RuleID:      "something-else",
				Description: "Unknown type",
				File:        "/path/to/file",
				StartLine:   20,
			},
			then: cdx.Component{
				Name:        "something-else",
				Description: "Unknown type",
				Type:        cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
					RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
						Type: cdx.RelatedCryptoMaterialTypeUnknown,
					},
				},
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{
							Location: "/path/to/file",
							Line:     intPtr(20),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			got, ignored := cdxprops.LeakToComponent(t.Context(), tt.given)
			require.Equal(t, tt.then, got)
			require.Equal(t, tt.ignored, ignored)
		})
	}
}

// helper function to create int pointer
func intPtr(i int) *int {
	return &i
}
