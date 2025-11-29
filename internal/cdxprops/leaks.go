package cdxprops

import (
	"context"
	"fmt"
	"strings"

	"github.com/zricethezav/gitleaks/v8/report"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func (c Converter) leakToComponent(_ context.Context, location string, finding report.Finding) (cdx.Component, bool) {
	var cryptoType cdx.RelatedCryptoMaterialType
	switch {
	case finding.RuleID == "private-key":
		cryptoType = cdx.RelatedCryptoMaterialTypePrivateKey
	case strings.Contains(finding.RuleID, "jwt"):
		cryptoType = cdx.RelatedCryptoMaterialTypeToken
	case strings.Contains(finding.RuleID, "token"):
		cryptoType = cdx.RelatedCryptoMaterialTypeToken
	case strings.Contains(finding.RuleID, "key"):
		cryptoType = cdx.RelatedCryptoMaterialTypeKey
	case strings.Contains(finding.RuleID, "password"):
		cryptoType = cdx.RelatedCryptoMaterialTypePassword
	default:
		cryptoType = cdx.RelatedCryptoMaterialTypeUnknown
	}

	bomRef := fmt.Sprintf("crypto/%s/%s", string(cryptoType), c.bomRefHasher([]byte(finding.Secret)))

	compo := cdx.Component{
		BOMRef:      bomRef,
		Name:        finding.RuleID,
		Description: finding.Description,
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
					Location: location,
					Line:     &finding.StartLine,
				},
			},
		},
	}

	return compo, false
}
