package theia_test

import (
	"os"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/theia"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestTheiaParsePEM(t *testing.T) {
	t.Parallel()
	var testCases = []struct {
		scenario string
		given    []byte
	}{
		{
			scenario: "PRIVATE KEY",
			given:    pems.privateKey,
		},
		{
			scenario: "EC PRIVATE KEY",
			given:    pems.ecPrivateKEy,
		},
		{
			scenario: "RSA PRIVATE KEY",
			given:    pems.rsaPrivateKey,
		},
		{
			scenario: "PUBLIC KEY",
			given:    pems.publicKey,
		},
		{
			scenario: "OPENSSH PRIVATE KEY",
			given:    pems.sshPrivateKey,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			t.Parallel()

			blocks, err := theia.ParsePEM(pems.rsaPrivateKey)
			require.NoError(t, err)

			cbom := theia.NewCBOM()
			for _, block := range blocks {
				components, err := theia.PEMToComponents(block)
				require.NoError(t, err)
				cbom.AddComponents(components)
			}
			err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).SetPretty(true).Encode(cbom.CDX())
			require.NoError(t, err)
		})
	}
}
