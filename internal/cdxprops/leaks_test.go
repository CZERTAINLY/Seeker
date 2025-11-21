package cdxprops_test

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/Seeker/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestLeakToComponent(t *testing.T) {
	key, err := cdxtest.GenECPrivateKey(elliptic.P224())
	require.NoError(t, err)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}
	content := pem.EncodeToMemory(pemBlock)

	cksum := func(s string) string {
		hash := sha256.Sum256([]byte(s))
		return "sha256:" + hex.EncodeToString(hash[:])
	}
	const jwtToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30`
	const apiKey = `AKIALALEMEL33243OLIA`
	const passwd = `nbusr123`

	var startLine = 42
	tests := []struct {
		scenario string
		given    model.Leak
		then     *model.Detection
	}{
		{
			scenario: "private key should be ignored",
			given: model.Leak{
				RuleID:    "private-key",
				File:      "privKey.pem",
				StartLine: startLine,
				Content:   string(content),
			},
			then: nil,
		},
		{
			scenario: "jwt token detection",
			given: model.Leak{
				RuleID:      "jwt-token",
				Description: "Found JWT token",
				File:        "/path/to/file",
				StartLine:   42,
				Content:     jwtToken,
			},
			then: &model.Detection{
				Source:   "LEAKS",
				Type:     "TOKEN",
				Location: "/path/to/file",
				Components: []cdx.Component{
					{
						BOMRef:      "crypto/token/" + cksum(jwtToken),
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
			},
		},
		{
			scenario: "api key detection",
			given: model.Leak{
				RuleID:      "api-key",
				Description: "Found API key",
				File:        "/path/to/file",
				StartLine:   10,
				Content:     apiKey,
			},
			then: &model.Detection{
				Source:   "LEAKS",
				Type:     "KEY",
				Location: "/path/to/file",
				Components: []cdx.Component{
					{
						BOMRef:      "crypto/key/" + cksum(apiKey),
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
			},
		},
		{
			scenario: "password detection",
			given: model.Leak{
				RuleID:      "password-leak",
				Description: "Found password",
				File:        "/path/to/file",
				StartLine:   15,
				Content:     passwd,
			},
			then: &model.Detection{
				Source:   "LEAKS",
				Type:     "PASSWORD",
				Location: "/path/to/file",
				Components: []cdx.Component{
					{
						BOMRef:      "crypto/password/" + cksum(passwd),
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
			then: &model.Detection{
				Source:   "LEAKS",
				Type:     "UNKNOWN",
				Location: "/path/to/file",
				Components: []cdx.Component{
					{
						BOMRef:      "crypto/unknown/sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
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
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {

			var c = cdxprops.NewConverter()
			detection := c.Leak(t.Context(), tt.given)
			if tt.then == nil {
				require.Nil(t, detection)
				return
			}
			require.Equal(t, tt.then, detection)
		})
	}
}

// helper function to create int pointer
func intPtr(i int) *int {
	return &i
}
