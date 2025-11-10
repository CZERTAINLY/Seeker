package bom

import (
	"io"
	"runtime/debug"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
)

var version string

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		version = "unknown"
	} else {
		version = info.Main.Version
	}
}

// Builder is a builder pattern for a CycloneDX BOM structure
type Builder struct {
	authors      []cdx.OrganizationalContact
	components   []cdx.Component
	dependencies []cdx.Dependency
	properties   []cdx.Property
}

func NewBuilder() *Builder {
	return &Builder{
		// those MUST be initialized as cyclone-dx JSON schema do not allow items to be null
		components:   []cdx.Component{},
		dependencies: []cdx.Dependency{},
		properties:   []cdx.Property{},
	}
}

func (b *Builder) AppendAuthors(authors ...cdx.OrganizationalContact) *Builder {
	b.authors = append(b.authors, authors...)
	return b
}

func (b *Builder) AppendComponents(components ...cdx.Component) *Builder {
	b.components = append(b.components, components...)
	return b
}

func (b *Builder) AppendProperties(properties ...cdx.Property) *Builder {
	b.properties = append(b.properties, properties...)
	return b
}

func (b *Builder) AppendDependencies(dependencies ...cdx.Dependency) *Builder {
	b.dependencies = append(b.dependencies, dependencies...)
	return b
}

// BOM returns a cdx.BOM based on a data inside the Builder
func (b *Builder) BOM() cdx.BOM {
	bom := cdx.BOM{
		JSONSchema:   "https://cyclonedx.org/schema/bom-1.6.schema.json",
		BOMFormat:    "CycloneDX",
		SpecVersion:  cdx.SpecVersion1_6,
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: &cdx.Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Lifecycles: &[]cdx.Lifecycle{
				{
					Name:        "",
					Phase:       "operations",
					Description: "",
				},
			},
			Authors: &b.authors,
			// This can't be not nil otherwise this error will happen
			// json: error calling MarshalJSON for type *cyclonedx.ToolsChoice: unexpected end of JSON input
			Component: &cdx.Component{
				Type:    "application",
				Name:    "Seeker",
				Version: version,
				Manufacturer: &cdx.OrganizationalEntity{
					Name:    "CZERTAINLY",
					Address: &cdx.PostalAddress{},
					URL: &[]string{
						"https://www.czertainly.com",
					},
				},
			},
		},
		Components:   &b.components,
		Dependencies: &b.dependencies,
		Properties:   &b.properties,
	}
	return bom
}

// AsJSON encode the BOM into JSON format
func (b *Builder) AsJSON(w io.Writer) error {
	bom := b.BOM()
	return cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON).SetPretty(true).Encode(&bom)
}
