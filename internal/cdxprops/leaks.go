package cdxprops

import (
	"context"
	"fmt"
	"strings"

	"github.com/CZERTAINLY/Seeker/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func (c Converter) leakToComponent(_ context.Context, leak model.Leak) (cdx.Component, bool) {
	var cryptoType cdx.RelatedCryptoMaterialType
	switch {
	case leak.RuleID == "private-key":
		return cdx.Component{}, true
	case strings.Contains(leak.RuleID, "jwt"):
		cryptoType = cdx.RelatedCryptoMaterialTypeToken
	case strings.Contains(leak.RuleID, "token"):
		cryptoType = cdx.RelatedCryptoMaterialTypeToken
	case strings.Contains(leak.RuleID, "key"):
		cryptoType = cdx.RelatedCryptoMaterialTypeKey
	case strings.Contains(leak.RuleID, "password"):
		cryptoType = cdx.RelatedCryptoMaterialTypePassword
	default:
		cryptoType = cdx.RelatedCryptoMaterialTypeUnknown
	}

	bomRef := fmt.Sprintf("crypto/%s/%s", string(cryptoType), c.bomRefHasher([]byte(leak.Content)))

	compo := cdx.Component{
		BOMRef:      bomRef,
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
