package gitleaks

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

type Detector struct {
	pool sync.Pool
	mx   sync.Mutex
}

func NewDetector() (*Detector, error) {
	first, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("creating new gitleaks detector: %w", err)
	}
	d := &Detector{}
	d.pool = sync.Pool{
		New: func() any {
			d.mx.Lock()
			defer d.mx.Unlock()
			detector, err := detect.NewDetectorDefaultConfig()
			if err != nil {
				panic(err)
			}
			return detector
		},
	}
	d.pool.Put(first)
	return d, nil
}

// Detect uses github.com/zricethezav/gitleaks/v8 to detect possible leaked files
// This method is SAFE to be called from multiple goroutines
func (d *Detector) Detect(ctx context.Context, b []byte, path string) ([]model.Detection, error) {
	detector := d.pool.Get().(*detect.Detector)
	defer d.pool.Put(detector)

	var compos []cdx.Component
	for _, finding := range detector.DetectString(string(b)) {
		compo, skip := findingToComponent(finding)
		if skip {
			continue
		}
		cdxprops.AddEvidenceLocation(&compo, path)
		compos = append(compos, compo)
	}

	if len(compos) == 0 {
		return nil, nil
	}

	return []model.Detection{
		{
			Components: compos,
			Path:       path,
		},
	}, nil
}

func findingToComponent(finding report.Finding) (cdx.Component, bool) {
	var zero cdx.Component
	var cryptoType cdx.RelatedCryptoMaterialType
	switch {
	case finding.RuleID == "private-key":
		// private keys are identified by internal/x509, no need here
		return zero, true
	case strings.Contains(finding.RuleID, "jwt"):
		fallthrough
	case strings.Contains(finding.RuleID, "token"):
		cryptoType = cdx.RelatedCryptoMaterialTypeToken
	case strings.Contains(finding.RuleID, "key"):
		cryptoType = cdx.RelatedCryptoMaterialTypeKey
	case strings.Contains(finding.RuleID, "password"):
		cryptoType = cdx.RelatedCryptoMaterialTypePassword
	default:
		cryptoType = cdx.RelatedCryptoMaterialTypeUnknown
	}

	return cdx.Component{
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
					Location: finding.File,
					Line:     &finding.StartLine,
				},
			},
		},
	}, false
}
