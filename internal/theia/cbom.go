package theia

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	theia "github.com/IBM/cbomkit-theia/provider/cyclonedx"
)

type CBOM struct {
	bom *cdx.BOM
}

func NewCBOM() CBOM {
	bom := cdx.BOM{
		SpecVersion: cdx.SpecVersion1_6,
		Metadata: &cdx.Metadata{
			Tools: &cdx.ToolsChoice{
				Services: &[]cdx.Service{
					{
						Provider: &cdx.OrganizationalEntity{
							Name: "CZERTAINLY",
						},
						Name:        "Seeker",
						Version:     "edge",
						Description: "CZERTAINLY Seeker",
						Services: &[]cdx.Service{
							{
								Name: "certificates",
							},
						},
					},
				},
			},
		},
	}
	return CBOM{bom: &bom}
}
func (c CBOM) AddComponents(components []cdx.Component) {
	theia.AddComponents(c.bom, components)
}

func (c CBOM) AddDependencies(dependencyMap map[cdx.BOMReference][]string) {
	theia.AddDependencies(c.bom, dependencyMap)
}

func (c CBOM) CDX() *cdx.BOM {
	return c.bom
}
