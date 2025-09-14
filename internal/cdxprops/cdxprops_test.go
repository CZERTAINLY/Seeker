package cdxprops

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestSetComponentProp_InitializesWhenNil(t *testing.T) {
	var c cdx.Component
	SetComponentProp(&c, CzertainlyComponentCertificateSourceFormat, "PEM")

	require.NotNil(t, c.Properties)
	props := *c.Properties
	require.Len(t, props, 1)
	require.Equal(t, CzertainlyComponentCertificateSourceFormat, props[0].Name)
	require.Equal(t, "PEM", props[0].Value)
}

func TestSetComponentProp_UpsertsExisting(t *testing.T) {
	c := cdx.Component{
		Properties: &[]cdx.Property{
			{Name: CzertainlyComponentCertificateSourceFormat, Value: "DER"},
			{Name: "other", Value: "x"},
		},
	}

	// change DER -> PEM, ensure no duplicate and length unchanged
	SetComponentProp(&c, CzertainlyComponentCertificateSourceFormat, "PEM")

	require.NotNil(t, c.Properties)
	props := *c.Properties
	require.Len(t, props, 2)

	// find the updated property
	found := false
	for _, p := range props {
		if p.Name == CzertainlyComponentCertificateSourceFormat {
			require.Equal(t, "PEM", p.Value)
			found = true
		}
	}
	require.True(t, found, "expected upserted property to exist")
}

func TestSetComponentProp_AppendsNew(t *testing.T) {
	c := cdx.Component{
		Properties: &[]cdx.Property{
			{Name: "existing", Value: "1"},
		},
	}

	SetComponentProp(&c, CzertainlyComponentCertificateBase64Content, "BASE64DATA")

	props := *c.Properties
	require.Len(t, props, 2)

	// verify both present
	var haveExisting, haveNew bool
	for _, p := range props {
		if p.Name == "existing" && p.Value == "1" {
			haveExisting = true
		}
		if p.Name == CzertainlyComponentCertificateBase64Content && p.Value == "BASE64DATA" {
			haveNew = true
		}
	}
	require.True(t, haveExisting)
	require.True(t, haveNew)
}

func TestSetComponentProp_EmptyValueIsNoop(t *testing.T) {
	// when Properties is nil, empty value should not allocate or change anything
	var c cdx.Component
	SetComponentProp(&c, "anything", "")
	require.Nil(t, c.Properties)

	// when Properties already exists, empty value should not modify
	c = cdx.Component{
		Properties: &[]cdx.Property{{Name: "keep", Value: "me"}},
	}
	SetComponentProp(&c, "new", "")
	props := *c.Properties
	require.Len(t, props, 1)
	require.Equal(t, "keep", props[0].Name)
	require.Equal(t, "me", props[0].Value)
}

func TestAddEvidenceLocation_InitializesWhenNil(t *testing.T) {
	var c cdx.Component
	AddEvidenceLocation(&c, "/abs/path")
	require.NotNil(t, c.Evidence)
	require.NotNil(t, c.Evidence.Occurrences)

	occs := *c.Evidence.Occurrences
	require.Len(t, occs, 1)
	require.Equal(t, "/abs/path", occs[0].Location)
}

func TestAddEvidenceLocation_Appends(t *testing.T) {
	c := cdx.Component{
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: "/first"},
			},
		},
	}
	AddEvidenceLocation(&c, "/second")

	occs := *c.Evidence.Occurrences
	require.Len(t, occs, 2)
	require.Equal(t, "/first", occs[0].Location)
	require.Equal(t, "/second", occs[1].Location)
}

func TestAddEvidenceLocation_NoOpOnEmpty(t *testing.T) {
	// case 1: empty on nil evidence
	var c1 cdx.Component
	AddEvidenceLocation(&c1, "")
	require.Nil(t, c1.Evidence)

	// case 2: empty on existing occurrences
	c2 := cdx.Component{
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{{Location: "/keep"}},
		},
	}
	AddEvidenceLocation(&c2, "")
	require.NotNil(t, c2.Evidence)
	require.NotNil(t, c2.Evidence.Occurrences)
	occs := *c2.Evidence.Occurrences
	require.Len(t, occs, 1)
	require.Equal(t, "/keep", occs[0].Location)
}
