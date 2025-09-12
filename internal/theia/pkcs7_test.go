package theia_test

import (
	"os"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/theia"
	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/stretchr/testify/require"
)

func TestTheiaParsePKCS7(t *testing.T) {
	certs, err := theia.ParsePKCS7(pems.pkcs7, "testdata/signed-data.p7s")
	require.NoError(t, err)

	cbom := theia.NewCBOM()
	for _, cert := range certs {
		components, deps, err := theia.X509ToComponents(cert)
		require.NoError(t, err)
		cbom.AddComponents(components)
		cbom.AddDependencies(deps)
	}
	err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).SetPretty(true).Encode(cbom.CDX())
	require.NoError(t, err)
}
