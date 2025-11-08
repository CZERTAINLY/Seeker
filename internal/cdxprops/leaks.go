package cdxprops

import (
	"context"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"

	"github.com/CZERTAINLY/Seeker/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// LeakToComponent converts the finding to a component.
// Private keys are now processed and converted to components,
// with their content base64-encoded.
func LeakToComponent(ctx context.Context, leak model.Leak) (cdx.Component, bool) {
	var cryptoType cdx.RelatedCryptoMaterialType
	switch {
	case leak.RuleID == "private-key":
		cryptoType = cdx.RelatedCryptoMaterialTypePrivateKey
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

	if leak.RuleID == "private-key" && leak.Content != "" {
		err := setCzertainlyProps(leak, &compo)
		if err != nil {
			slog.WarnContext(ctx, "can't process private-key leak: ignoring", "error", err)
			return cdx.Component{}, true
		}
	}
	return compo, false
}

func setCzertainlyProps(leak model.Leak, compop *cdx.Component) error {
	raw := []byte(leak.Content)
	block, _ := pem.Decode(raw)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	SetComponentProp(compop, CzertainlyPrivateKeyType, block.Type)
	SetComponentBase64Prop(compop, CzertainlyPrivateKeyBase64Content, raw)
	return nil
}
