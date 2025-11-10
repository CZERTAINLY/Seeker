package bom

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	jss "github.com/kaptinlin/jsonschema"
)

//go:embed schemas/bom-1.6.schema.json
var schemaFS embed.FS

var versionToPath = map[cdx.SpecVersion]string{
	cdx.SpecVersion1_6: "schemas/bom-1.6.schema.json",
}

// Validator validates the CycloneDX BOM against the schema
type Validator struct {
	schemas map[cdx.SpecVersion]*jss.Schema
}

func NewValidator(versions ...cdx.SpecVersion) (Validator, error) {
	var zero Validator
	schemas := make(map[cdx.SpecVersion]*jss.Schema, 1)
	for _, ver := range versions {
		path, ok := versionToPath[ver]
		if !ok {
			return zero, fmt.Errorf("unknown schema version: %s", ver)
		}
		b, err := schemaFS.ReadFile(path)
		if err != nil {
			return zero, fmt.Errorf("reading embedded schema: %w", err)
		}
		compiler := jss.NewCompiler()
		schema, err := compiler.Compile(b)
		if err != nil {
			return zero, fmt.Errorf("compiling schema: %w", err)
		}
		schemas[ver] = schema
	}
	return Validator{
		schemas: schemas,
	}, nil
}

func (v Validator) Validate(ctx context.Context, bom *cdx.BOM) error {
	schema, err := v.versionToSchema(bom.SpecVersion)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	err = encoder.Encode(bom)
	if err != nil {
		return fmt.Errorf("encoding bom to JSON: %w", err)
	}
	return v.validateBytes(ctx, schema, buf.Bytes())
}

func (v Validator) ValidateBytes(ctx context.Context, b []byte) error {
	var bom struct {
		SpecVersion cdx.SpecVersion `json:"specVersion"`
	}
	err := json.Unmarshal(b, &bom)
	if err != nil {
		return fmt.Errorf("reading spec version: %w", err)
	}

	schema, err := v.versionToSchema(bom.SpecVersion)
	if err != nil {
		return err
	}
	return v.validateBytes(ctx, schema, b)
}

func (v Validator) versionToSchema(version cdx.SpecVersion) (*jss.Schema, error) {
	schema, ok := v.schemas[version]
	if !ok {
		supported := make([]string, 0, len(v.schemas))
		for k := range v.schemas {
			supported = append(supported, k.String())
		}
		return nil, fmt.Errorf("unsupported BOM specification version: supported %s: got: %s",
			strings.Join(supported, ","),
			version,
		)
	}
	return schema, nil
}

func (v Validator) validateBytes(ctx context.Context, schema *jss.Schema, b []byte) error {
	res := schema.Validate(b)
	if !res.Valid {
		var errorMsgs []string
		for _, err := range res.Errors {
			errorMsgs = append(errorMsgs, fmt.Sprintf("%s: %s", err.Keyword, err.Error()))
		}
		// Join all errors with newlines for readability
		return fmt.Errorf("BOM validation failed:\n%s", strings.Join(errorMsgs, "\n"))
	}
	return nil
}
