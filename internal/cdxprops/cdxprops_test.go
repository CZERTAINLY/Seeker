package cdxprops_test

import (
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/Seeker/internal/scanner/pem"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestSetComponentProp_InitializesWhenNil(t *testing.T) {
	var c cdx.Component
	cdxprops.SetComponentProp(&c, cdxprops.CzertainlyComponentCertificateSourceFormat, "PEM")

	require.NotNil(t, c.Properties)
	props := *c.Properties
	require.Len(t, props, 1)
	require.Equal(t, cdxprops.CzertainlyComponentCertificateSourceFormat, props[0].Name)
	require.Equal(t, "PEM", props[0].Value)
}

func TestSetComponentProp_UpsertsExisting(t *testing.T) {
	c := cdx.Component{
		Properties: &[]cdx.Property{
			{Name: cdxprops.CzertainlyComponentCertificateSourceFormat, Value: "DER"},
			{Name: "other", Value: "x"},
		},
	}

	// change DER -> PEM, ensure no duplicate and length unchanged
	cdxprops.SetComponentProp(&c, cdxprops.CzertainlyComponentCertificateSourceFormat, "PEM")

	require.NotNil(t, c.Properties)
	props := *c.Properties
	require.Len(t, props, 2)

	// find the updated property
	found := false
	for _, p := range props {
		if p.Name == cdxprops.CzertainlyComponentCertificateSourceFormat {
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

	cdxprops.SetComponentProp(&c, cdxprops.CzertainlyComponentCertificateBase64Content, "BASE64DATA")

	props := *c.Properties
	require.Len(t, props, 2)

	// verify both present
	var haveExisting, haveNew bool
	for _, p := range props {
		if p.Name == "existing" && p.Value == "1" {
			haveExisting = true
		}
		if p.Name == cdxprops.CzertainlyComponentCertificateBase64Content && p.Value == "BASE64DATA" {
			haveNew = true
		}
	}
	require.True(t, haveExisting)
	require.True(t, haveNew)
}

func TestSetComponentProp_EmptyValueIsNoop(t *testing.T) {
	// when Properties is nil, empty value should not allocate or change anything
	var c cdx.Component
	cdxprops.SetComponentProp(nil, "anything", "")
	require.Nil(t, c.Properties)
	cdxprops.SetComponentProp(&c, "anything", "")
	require.Nil(t, c.Properties)
	cdxprops.SetComponentProp(&c, "", "anything")
	require.Nil(t, c.Properties)

	// when Properties already exists, empty value should not modify
	c = cdx.Component{
		Properties: &[]cdx.Property{{Name: "keep", Value: "me"}},
	}
	cdxprops.SetComponentProp(&c, "new", "")
	props := *c.Properties
	require.Len(t, props, 1)
	require.Equal(t, "keep", props[0].Name)
	require.Equal(t, "me", props[0].Value)
}

func TestAddEvidenceLocation_InitializesWhenNil(t *testing.T) {
	var c cdx.Component
	cdxprops.AddEvidenceLocation(&c, "/abs/path")
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
	cdxprops.AddEvidenceLocation(&c, "/second")

	occs := *c.Evidence.Occurrences
	require.Len(t, occs, 2)
	require.Equal(t, "/first", occs[0].Location)
	require.Equal(t, "/second", occs[1].Location)
}

func TestAddEvidenceLocation_NoOpOnEmpty(t *testing.T) {
	// case 1: empty on nil evidence
	var c1 cdx.Component
	cdxprops.AddEvidenceLocation(&c1, "")
	require.Nil(t, c1.Evidence)

	// case 2: empty on existing occurrences
	c2 := cdx.Component{
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{{Location: "/keep"}},
		},
	}
	cdxprops.AddEvidenceLocation(&c2, "")
	require.NotNil(t, c2.Evidence)
	require.NotNil(t, c2.Evidence.Occurrences)
	occs := *c2.Evidence.Occurrences
	require.Len(t, occs, 1)
	require.Equal(t, "/keep", occs[0].Location)
}

func TestSetComponentBase64Prop(t *testing.T) {
	scenarios := []struct {
		scenario  string
		given     *cdx.Component
		whenName  string
		whenValue []byte
		thenValue string
	}{
		{
			scenario:  "Given empty component, when setting new base64 property",
			given:     &cdx.Component{},
			whenName:  "test-prop",
			whenValue: []byte("hello world"),
			thenValue: "aGVsbG8gd29ybGQ=",
		},
		{
			scenario: "Given component with existing property, when updating with base64 value",
			given: &cdx.Component{
				Properties: &[]cdx.Property{
					{Name: "test-prop", Value: "old-value"},
				},
			},
			whenName:  "test-prop",
			whenValue: []byte("hello world"),
			thenValue: "aGVsbG8gd29ybGQ=",
		},
		{
			scenario:  "Given component, when setting empty value",
			given:     &cdx.Component{},
			whenName:  "test-prop",
			whenValue: []byte{},
			thenValue: "",
		},
	}

	for _, s := range scenarios {
		t.Run(s.scenario, func(t *testing.T) {
			require := require.New(t)

			// When
			cdxprops.SetComponentBase64Prop(s.given, s.whenName, s.whenValue)

			// Then
			if s.thenValue == "" {
				require.Nil(s.given.Properties, "Properties should be nil for empty value")
				return
			}

			require.NotNil(s.given.Properties, "Properties should not be nil")

			var foundProp *cdx.Property
			for _, prop := range *s.given.Properties {
				if prop.Name == s.whenName {
					foundProp = &prop
					break
				}
			}

			require.NotNil(foundProp, "Property should exist")
			require.Equal(s.thenValue, foundProp.Value, "Property value should match expected base64 value")
		})
	}
}

func TestMLMKEMPrivateKey(t *testing.T) {
	pk, err := cdxtest.TestData(cdxtest.MLKEM1024PrivateKey)
	require.NoError(t, err)

	bundle, err := pem.Scanner{}.Scan(t.Context(), pk, cdxtest.MLKEM1024PrivateKey)
	require.NoError(t, err)

	compos, err := cdxprops.PEMBundleToCDX(t.Context(), bundle, cdxtest.MLKEM1024PrivateKey)
	require.NoError(t, err)

	require.Len(t, compos, 1)
	require.Equal(t, "ML-KEM-1024", compos[0].Name)
}
