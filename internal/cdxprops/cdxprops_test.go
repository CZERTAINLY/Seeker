package cdxprops_test

import (
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/Seeker/internal/scanner/pem"

	"github.com/stretchr/testify/require"
)

func TestMLMKEMPrivateKey(t *testing.T) {
	pk, err := cdxtest.TestData(cdxtest.MLKEM1024PrivateKey)
	require.NoError(t, err)

	bundle, err := pem.Scanner{}.Scan(t.Context(), pk, cdxtest.MLKEM1024PrivateKey)
	require.NoError(t, err)

	c := cdxprops.NewConverter()
	compos, err := c.PEMBundleToCDX(t.Context(), bundle, cdxtest.MLKEM1024PrivateKey)
	require.NoError(t, err)

	require.Len(t, compos, 1)
	require.Equal(t, "ML-KEM-1024", compos[0].Name)
}
