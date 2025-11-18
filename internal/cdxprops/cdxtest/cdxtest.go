package cdxtest

import (
	"crypto/x509"
	"embed"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

//go:embed testdata/*
var data embed.FS

const MLKEM1024PrivateKey = "testdata/ml-kem-1024-private-key.pem"

func TestData(path string) ([]byte, error) {
	return data.ReadFile(path)
}

// getProp gets a property value from a CDX component
func GetProp(comp cdx.Component, name string) string {
	if comp.Properties == nil {
		return ""
	}
	for _, p := range *comp.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// HasEvidencePath checks that the component has the expected evidence path
func HasEvidencePath(comp cdx.Component) error {
	if comp.Evidence == nil {
		return fmt.Errorf("evidence is nil")
	}
	if comp.Evidence.Occurrences == nil {
		return fmt.Errorf("evidence occurrences is nil")
	}
	if len(*comp.Evidence.Occurrences) < 1 {
		return fmt.Errorf("evidence occurrences is empty")
	}

	loc := (*comp.Evidence.Occurrences)[0].Location
	if loc == "" {
		return fmt.Errorf("location is empty")
	}

	abs, err := filepath.Abs("testpath")
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	if !filepath.IsAbs(loc) {
		return fmt.Errorf("location path is not absolute: %s", loc)
	}

	if !strings.HasSuffix(loc, filepath.Clean(abs)) {
		return fmt.Errorf("location %s does not have expected suffix %s", loc, filepath.Clean(abs))
	}

	return nil
}

func HasFormatAndDERBase64(comp cdx.Component, formatKey, base64Key string) error {
	format := GetProp(comp, formatKey)
	if format == "" {
		return fmt.Errorf("certificate format property is empty")
	}

	b64 := GetProp(comp, base64Key)
	if b64 == "" {
		return fmt.Errorf("certificate base64 content property is empty")
	}

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("failed to decode base64 content: %w", err)
	}

	_, err = x509.ParseCertificate(raw)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	return nil
}
