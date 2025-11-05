package cdxtest_test

import (
	"crypto/x509"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops/cdxtest"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestGenSelfSignedCert(t *testing.T) {
	// Generate the self-signed certificate
	cert, err := cdxtest.GenSelfSignedCert()

	// require no error occurred
	require.NoError(t, err)

	// Verify the certificate is not nil and contains expected values
	require.NotNil(t, cert.Der)
	require.NotNil(t, cert.Cert)
	require.NotNil(t, cert.Key)

	// Verify certificate fields
	require.Equal(t, "Test Cert", cert.Cert.Subject.CommonName)
	require.True(t, cert.Cert.BasicConstraintsValid)

	// Verify key usage
	expectedKeyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	require.Equal(t, expectedKeyUsage, cert.Cert.KeyUsage)

	// Verify ExtKeyUsage
	require.Contains(t, cert.Cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
}

func TestGetProp(t *testing.T) {
	tests := []struct {
		name     string
		comp     cdx.Component
		propName string
		want     string
	}{
		{
			name: "existing property",
			comp: cdx.Component{
				Properties: &[]cdx.Property{
					{Name: "test", Value: "value"},
					{Name: "other", Value: "othervalue"},
				},
			},
			propName: "test",
			want:     "value",
		},
		{
			name: "non-existing property",
			comp: cdx.Component{
				Properties: &[]cdx.Property{
					{Name: "test", Value: "value"},
				},
			},
			propName: "notfound",
			want:     "",
		},
		{
			name:     "nil properties",
			comp:     cdx.Component{},
			propName: "test",
			want:     "",
		},
		{
			name: "empty properties",
			comp: cdx.Component{
				Properties: &[]cdx.Property{},
			},
			propName: "test",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cdxtest.GetProp(tt.comp, tt.propName)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestHasEvidencePath(t *testing.T) {
	absPath, err := filepath.Abs("testpath")
	require.NoError(t, err)

	tests := []struct {
		name    string
		comp    cdx.Component
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil evidence",
			comp:    cdx.Component{},
			wantErr: true,
			errMsg:  "evidence is nil",
		},
		{
			name: "nil occurrences",
			comp: cdx.Component{
				Evidence: &cdx.Evidence{},
			},
			wantErr: true,
			errMsg:  "evidence occurrences is nil",
		},
		{
			name: "empty occurrences",
			comp: cdx.Component{
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{},
				},
			},
			wantErr: true,
			errMsg:  "evidence occurrences is empty",
		},
		{
			name: "empty location",
			comp: cdx.Component{
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{Location: ""},
					},
				},
			},
			wantErr: true,
			errMsg:  "location is empty",
		},
		{
			name: "relative path location",
			comp: cdx.Component{
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{Location: "relative/path"},
					},
				},
			},
			wantErr: true,
			errMsg:  "location path is not absolute: relative/path",
		},
		{
			name: "wrong suffix",
			comp: cdx.Component{
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{Location: "/absolute/wrong/path"},
					},
				},
			},
			wantErr: true,
			errMsg:  "location /absolute/wrong/path does not have expected suffix " + filepath.Clean(absPath),
		},
		{
			name: "valid evidence path",
			comp: cdx.Component{
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{Location: filepath.Join("/some/path", filepath.Clean(absPath))},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cdxtest.HasEvidencePath(tt.comp)
			if tt.wantErr {
				require.Error(t, err)
				require.Equal(t, tt.errMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestHasFormatAndDERBase64(t *testing.T) {
	// Test constants
	const (
		formatKey  = "test.format"
		base64Key  = "test.content"
		certFormat = "DER"
	)

	// Generate a valid test certificate
	cert, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	validB64 := base64.StdEncoding.EncodeToString(cert.Der)

	tests := []struct {
		name    string
		comp    cdx.Component
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil properties",
			comp:    cdx.Component{},
			wantErr: true,
			errMsg:  "certificate format property is empty",
		},
		{
			name: "empty format",
			comp: cdx.Component{
				Properties: &[]cdx.Property{
					{Name: base64Key, Value: validB64},
				},
			},
			wantErr: true,
			errMsg:  "certificate format property is empty",
		},
		{
			name: "empty base64",
			comp: cdx.Component{
				Properties: &[]cdx.Property{
					{Name: formatKey, Value: certFormat},
				},
			},
			wantErr: true,
			errMsg:  "certificate base64 content property is empty",
		},
		{
			name: "invalid base64",
			comp: cdx.Component{
				Properties: &[]cdx.Property{
					{Name: formatKey, Value: certFormat},
					{Name: base64Key, Value: "invalid-base64"},
				},
			},
			wantErr: true,
			errMsg:  "failed to decode base64 content:",
		},
		{
			name: "invalid certificate",
			comp: cdx.Component{
				Properties: &[]cdx.Property{
					{Name: formatKey, Value: certFormat},
					{Name: base64Key, Value: "YWJjZGVm"}, // valid base64 but invalid cert
				},
			},
			wantErr: true,
			errMsg:  "failed to parse certificate:",
		},
		{
			name: "valid certificate",
			comp: cdx.Component{
				Properties: &[]cdx.Property{
					{Name: formatKey, Value: certFormat},
					{Name: base64Key, Value: validB64},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cdxtest.HasFormatAndDERBase64(tt.comp, formatKey, base64Key)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateEvidencePath(t *testing.T) {
	absPath, err := filepath.Abs("testpath")
	require.NoError(t, err)
	cleanPath := filepath.Clean(absPath)

	tests := []struct {
		scenario string
		given    cdx.Component
		then     struct {
			expectedErr bool
			errorMsg    string
		}
	}{
		{
			scenario: "nil evidence",
			given:    cdx.Component{},
			then: struct {
				expectedErr bool
				errorMsg    string
			}{
				expectedErr: true,
				errorMsg:    "evidence is nil",
			},
		},
		{
			scenario: "nil occurrences",
			given: cdx.Component{
				Evidence: &cdx.Evidence{},
			},
			then: struct {
				expectedErr bool
				errorMsg    string
			}{
				expectedErr: true,
				errorMsg:    "evidence occurrences is nil",
			},
		},
		{
			scenario: "empty occurrences",
			given: cdx.Component{
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{},
				},
			},
			then: struct {
				expectedErr bool
				errorMsg    string
			}{
				expectedErr: true,
				errorMsg:    "evidence occurrences must have at least one entry",
			},
		},
		{
			scenario: "empty location",
			given: cdx.Component{
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{Location: ""},
					},
				},
			},
			then: struct {
				expectedErr bool
				errorMsg    string
			}{
				expectedErr: true,
				errorMsg:    "evidence location is empty",
			},
		},
		{
			scenario: "relative path location",
			given: cdx.Component{
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{Location: "relative/path"},
					},
				},
			},
			then: struct {
				expectedErr bool
				errorMsg    string
			}{
				expectedErr: true,
				errorMsg:    "evidence location path is not absolute: relative/path",
			},
		},
		{
			scenario: "wrong suffix",
			given: cdx.Component{
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{Location: "/absolute/wrong/path"},
					},
				},
			},
			then: struct {
				expectedErr bool
				errorMsg    string
			}{
				expectedErr: true,
				errorMsg:    "evidence location /absolute/wrong/path does not have expected suffix " + cleanPath,
			},
		},
		{
			scenario: "valid path",
			given: cdx.Component{
				Evidence: &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{Location: filepath.Join("/some/prefix", cleanPath)},
					},
				},
			},
			then: struct {
				expectedErr bool
				errorMsg    string
			}{
				expectedErr: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			err := cdxtest.ValidateEvidencePath(tt.given)
			if tt.then.expectedErr {
				require.Error(t, err)
				require.Equal(t, tt.then.errorMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
