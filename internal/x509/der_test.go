package x509_test

import (
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/model"
	czX509 "github.com/CZERTAINLY/Seeker/internal/x509"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func Test_DER_Detection(t *testing.T) {
	der, _, _ := genSelfSignedCert(t)
	der2, _, _ := genSelfSignedCert(t)
	concatDER := append(append([]byte{}, der...), der2...)

	tests := []struct {
		name      string
		input     []byte
		wantMatch bool
	}{
		{"DER single", der, true},
		{"DER concatenated", concatDER, true},
		{"Invalid", []byte("not a cert"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d czX509.Detector
			got, err := d.Detect(t.Context(), tt.input, "testpath")
			if !tt.wantMatch {
				require.Error(t, err)
				require.ErrorIs(t, err, model.ErrNoMatch)
				return
			}
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.GreaterOrEqual(t, len(got[0].Components), 1)
			for _, comp := range got[0].Components {
				require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
				requireEvidencePath(t, comp)
				requireFormatAndDERBase64(t, comp)
			}
		})
	}
}