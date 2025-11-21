package czertainly_test

import (
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops/czertainly"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestCertificateProperties(t *testing.T) {
	tests := []struct {
		name   string
		props  []cdx.Property
		source string
		cert   *x509.Certificate
		want   []cdx.Property
	}{
		{
			name:   "nil",
			props:  nil,
			source: "TEST",
			cert: &x509.Certificate{
				Raw: []byte("hello, world"),
			},
			want: []cdx.Property{
				{
					Name:  czertainly.ComponentCertificateSourceFormat,
					Value: "TEST",
				},
				{
					Name:  czertainly.ComponentCertificateBase64Content,
					Value: base64.StdEncoding.EncodeToString([]byte("hello, world")),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := czertainly.CertificateProperties(tt.props, tt.source, tt.cert)
			require.Equal(t, tt.want, got)
		})
	}
}
