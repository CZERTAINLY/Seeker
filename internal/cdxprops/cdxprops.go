package cdxprops

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Exported so tests and other packages can reference the same strings.
const (
	CzertainlyComponentCertificateSourceFormat      = "czertainly:component:certificate:source_format"
	CzertainlyComponentCertificateBase64Content     = "czertainly:component:certificate:base64_content"
	CzertainlyComponentSSHHostKeyFingerprintContent = "czertainly:component:ssh_hostkey:fingerprint_content"
	CzertainlyComponentSSHHostKeyContent            = "czertainly:component:ssh_hostkey:content"
)

// Set (or upsert) a CycloneDX component property.
func SetComponentProp(c *cdx.Component, name, value string) {
	if value == "" {
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

// Add (append) an evidence.occurrence location if non-empty.
func AddEvidenceLocation(c *cdx.Component, loc string) {
	if loc == "" {
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
