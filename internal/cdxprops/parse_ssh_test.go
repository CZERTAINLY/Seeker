package cdxprops_test

import (
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestParseSSHAlgorithm(t *testing.T) {
	t.Parallel()

	_, ok := cdxprops.ParseSSHAlgorithm("unknown-algorithm")
	require.False(t, ok)

	algo, ok := cdxprops.ParseSSHAlgorithm("ecdsa-sha2-nistp256")
	require.True(t, ok)
	exp := cdx.CryptoAlgorithmProperties{
		Primitive:              cdx.CryptoPrimitiveSignature,
		ParameterSetIdentifier: "nistp256@1.2.840.10045.3.1.7",
		Curve:                  "nistp256",
		CryptoFunctions:        &[]cdx.CryptoFunction{cdx.CryptoFunctionVerify},
	}
	require.Equal(t, exp, algo)
}

func TestParseSSHHostKey(t *testing.T) {
	_, err := cdxprops.ParseSSHHostKey(model.SSHHostKey{
		Type: "unsupported-algo",
		Bits: "0",
	})
	require.Error(t, err)

	key := model.SSHHostKey{
		Type:        "ecdsa-sha2-nistp256",
		Bits:        "256",
		Key:         "AAAA-test-public-key",
		Fingerprint: "SHA256:dummyfingerprint",
	}

	compo, err := cdxprops.ParseSSHHostKey(key)
	require.NoError(t, err)

	require.Equal(t, "crypto/ssh-hostkey/"+key.Type+"@"+key.Bits, compo.BOMRef)
	require.Equal(t, key.Type, compo.Name)
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, compo.Type)
	require.NotNil(t, compo.CryptoProperties)

	cp := compo.CryptoProperties
	require.Equal(t, cdx.CryptoAssetTypeAlgorithm, cp.AssetType)
	require.NotNil(t, cp.AlgorithmProperties)

	algo := cp.AlgorithmProperties
	require.Equal(t, cdx.CryptoPrimitiveSignature, algo.Primitive)
	require.Equal(t, "nistp256@1.2.840.10045.3.1.7", algo.ParameterSetIdentifier)
	require.Equal(t, "nistp256", algo.Curve)
	require.Equal(t, algo.ParameterSetIdentifier, cp.OID)

	props := map[string]string{}
	if compo.Properties != nil {
		for _, p := range *compo.Properties {
			props[p.Name] = p.Value
		}
	}
	require.Equal(t, key.Key, props[cdxprops.CzertainlyComponentSSHHostKeyContent])
	require.Equal(t, key.Fingerprint, props[cdxprops.CzertainlyComponentSSHHostKeyFingerprintContent])
}
