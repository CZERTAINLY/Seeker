package theia_test

import (
	"os"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/theia"
	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/stretchr/testify/require"
)

func TestTheiaParseX509(t *testing.T) {
	certs, err := theia.ParseX509(pems.certificate, "testdata/cert.pem")
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

func TestTheiaParseX509BogusData(t *testing.T) {
	certs, err := theia.ParseX509([]byte("bogus data"), "testdata/bogus.dat")
	require.Error(t, err)
	require.Nil(t, certs)
}
