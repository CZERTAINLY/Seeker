package cdxprops

import (
	"strings"

	"github.com/CZERTAINLY/Seeker/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// LeakToComponent converts the finding to component
// it IGNORES private-key as this is expected to be
// detected by x509 code and not by regular expressions
func LeakToComponent(leak model.Leak) (cdx.Component, bool) {
	var zero cdx.Component
	var cryptoType cdx.RelatedCryptoMaterialType
	switch {
	case leak.RuleID == "private-key":
		return zero, true
	case strings.Contains(leak.RuleID, "jwt"):
		fallthrough
	case strings.Contains(leak.RuleID, "token"):
		cryptoType = cdx.RelatedCryptoMaterialTypeToken
	case strings.Contains(leak.RuleID, "key"):
		cryptoType = cdx.RelatedCryptoMaterialTypeKey
	case strings.Contains(leak.RuleID, "password"):
		cryptoType = cdx.RelatedCryptoMaterialTypePassword
	default:
		cryptoType = cdx.RelatedCryptoMaterialTypeUnknown
	}

	compo := cdx.Component{
		Name:        leak.RuleID,
		Description: leak.Description,
		Type:        cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: cryptoType,
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: leak.File,
					Line:     &leak.StartLine,
				},
			},
		},
	}
	return compo, false
}
