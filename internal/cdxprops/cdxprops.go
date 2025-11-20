package cdxprops

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/CZERTAINLY/Seeker/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Exported so tests and other packages can reference the same strings.
const (
	CzertainlyComponentCertificateSourceFormat      = "czertainly:component:certificate:source_format"
	CzertainlyComponentCertificateBase64Content     = "czertainly:component:certificate:base64_content"
	CzertainlyComponentSSHHostKeyFingerprintContent = "czertainly:component:ssh_hostkey:fingerprint_content"
	CzertainlyComponentSSHHostKeyContent            = "czertainly:component:ssh_hostkey:content"
	CzertainlyPrivateKeyType                        = "czertainly:component:private_key:type"
	CzertainlyPrivateKeyBase64Content               = "czertainly:component:private_key:base64_content"
)

type Converter struct {
	czertainly   bool
	bomRefHasher func([]byte) string
}

func NewConverter() Converter {
	return Converter{
		czertainly: false,
		bomRefHasher: func(b []byte) string {
			hash := sha256.Sum256(b)
			return "sha256:" + hex.EncodeToString(hash[:])
		},
	}
}

func (c Converter) WithCzertainlyExtenstions(czertainly bool) Converter {
	c.czertainly = true
	return c
}

// Leak converts the finding to detection.
// Supports jwt, token, key and password.
// Returns nil if given Leak should be ignored
// safe to be used by different go routines
func (c Converter) Leak(ctx context.Context, leak model.Leak) *model.Detection {
	compo, skip := c.leakToComponent(ctx, leak)
	if skip {
		return nil
	}
	typ := strings.ToUpper(string(compo.CryptoProperties.RelatedCryptoMaterialProperties.Type))
	return &model.Detection{
		Source:     "LEAKS",
		Type:       model.DetectionType(typ),
		Location:   leak.File,
		Components: []cdx.Component{compo},
	}
}

// Set (or upsert) a CycloneDX component property.
func SetComponentProp(c *cdx.Component, name, value string) {
	if name == "" || value == "" || c == nil {
		return
	}
	if c.Properties == nil {
		c.Properties = &[]cdx.Property{{Name: name, Value: value}}
		return
	}
	props := *c.Properties
	for i := range props {
		if props[i].Name == name {
			props[i].Value = value
			*c.Properties = props
			return
		}
	}
	props = append(props, cdx.Property{Name: name, Value: value})
	*c.Properties = props
}

func SetComponentBase64Prop(c *cdx.Component, name string, value []byte) {
	SetComponentProp(c, name, base64.StdEncoding.EncodeToString(value))
}

// Add (append) an evidence.occurrence location if non-empty.
func AddEvidenceLocation(c *cdx.Component, loc string) {
	if loc == "" || c == nil {
		return
	}
	occ := cdx.EvidenceOccurrence{Location: loc}
	if c.Evidence == nil {
		c.Evidence = &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{occ}}
		return
	}
	if c.Evidence.Occurrences == nil {
		c.Evidence.Occurrences = &[]cdx.EvidenceOccurrence{occ}
		return
	}
	occs := append(*c.Evidence.Occurrences, occ)
	c.Evidence.Occurrences = &occs
}
