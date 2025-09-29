package x509_test

import (
	"encoding/pem"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/model"
	czX509 "github.com/CZERTAINLY/Seeker/internal/x509"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func Test_PEM_Detection(t *testing.T) {
	der, _, _ := genSelfSignedCert(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	tests := []struct {
		name      string
		input     []byte
		wantMatch bool
	}{
		{"PEM single", pemBytes, true},
		{"Invalid", []byte("not a cert"), false},
		{"PEM not a cert", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), false},
		// Test TRUSTED CERTIFICATE type
		{"TRUSTED CERTIFICATE", pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: der}), true},
		// Test PKCS7 PEM block
		{"PKCS7 PEM", pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: []byte("fakepkcs7data")}), false}, // Will fail parsing but exercises path
		// Test CMS PEM block  
		{"CMS PEM", pem.EncodeToMemory(&pem.Block{Type: "CMS", Bytes: []byte("fakecmsdata")}), false}, // Will fail parsing but exercises path
		// Test PKCS12 PEM block with sniff failure
		{"PKCS12 PEM invalid", pem.EncodeToMemory(&pem.Block{Type: "PKCS12", Bytes: []byte("fakepkcs12data")}), false}, // Will fail sniffing
		// Test multiple PEM blocks with leading text
		{"Multiple blocks with text", append([]byte("Some random text\n"), append(pemBytes, pemBytes...)...), true},
		// Test malformed PEM
		{"Malformed PEM", []byte("-----BEGIN CERTIFICATE-----\nINVALID_DATA\n-----END CERTIFICATE-----"), false},
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
