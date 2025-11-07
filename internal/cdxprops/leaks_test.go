package cdxprops_test

import (
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/stretchr/testify/require"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestLeakToComponent(t *testing.T) {
	tests := []struct {
		scenario string
		given    model.Leak
		then     cdx.Component
		ignored  bool
	}{
		{
			scenario: "private key should return empty component",
			given: model.Leak{
				RuleID: "private-key",
			},
			then:    cdx.Component{},
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
			got, ignored := cdxprops.LeakToComponent(tt.given)
			require.Equal(t, tt.then, got)
			require.Equal(t, tt.ignored, ignored)
		})
	}
}

// helper function to create int pointer
func intPtr(i int) *int {
	return &i
}
