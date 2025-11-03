package cdxprops_test

import (
	"bytes"
	"encoding/json"
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

func TestParseTLSVersion(t *testing.T) {
	tests := []struct {
		scenario     string
		given        string
		wantProtocol string
		wantVersion  string
	}{
		{
			scenario:     "parse TLSv1.3",
			given:        "TLSv1.3",
			wantProtocol: "tls",
			wantVersion:  "1.3",
		},
		{
			scenario:     "parse SSLv2",
			given:        "SSLv2",
			wantProtocol: "ssl",
			wantVersion:  "2.0",
		},
		{
			scenario:     "parse alternative format",
			given:        "TLS 1.3",
			wantProtocol: "tls",
			wantVersion:  "1.3",
		},
		{
			scenario:     "unknown format",
			given:        "unknown",
			wantProtocol: "n/a",
			wantVersion:  "n/a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			protocol, version := cdxprops.ParseTLSVersion(tt.given)
			require.Equal(t, tt.wantProtocol, protocol)
			require.Equal(t, tt.wantVersion, version)
		})
	}
}

func TestParseTLSCiphers(t *testing.T) {
	tests := []struct {
		scenario   string
		given      []string
		wantLen    int
		wantAlgos  []cdx.BOMReference // algorithms for first cipher
		wantIdents []string           // identifiers for first cipher
	}{
		{
			scenario: "valid cipher suites",
			given: []string{
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			},
			wantLen: 2,
			wantAlgos: []cdx.BOMReference{
				"crypto/algorithm/ecdh-curve25519@1.3.132.1.12",
				"crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1",
				"crypto/algorithm/aes-256-gcm@2.16.840.1.101.3.4.1.46",
				"crypto/algorithm/sha-384@2.16.840.1.101.3.4.2.2",
			},
			wantIdents: []string{"0xC0", "0x30"},
		},
		{
			scenario: "mixed valid and invalid ciphers",
			given: []string{
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"INVALID_CIPHER_SUITE",
			},
			wantLen: 1,
			wantAlgos: []cdx.BOMReference{
				"crypto/algorithm/ecdh-curve25519@1.3.132.1.12",
				"crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1",
				"crypto/algorithm/aes-256-gcm@2.16.840.1.101.3.4.1.46",
				"crypto/algorithm/sha-384@2.16.840.1.101.3.4.2.2",
			},

			wantIdents: []string{"0xC0", "0x30"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			resultp := cdxprops.ParseTLSCiphers(t.Context(), tt.given)
			require.NotNil(t, resultp)
			result := *resultp

			// Check the length of returned slice
			require.Equal(t, tt.wantLen, len(result))

			if len(result) > 0 {
				// Check algorithms of first cipher suite
				require.NotNil(t, result[0].Algorithms)
				require.ElementsMatch(t, tt.wantAlgos, *result[0].Algorithms)

				// Check identifiers of first cipher suite
				require.NotNil(t, result[0].Identifiers)
				require.ElementsMatch(t, tt.wantIdents, *result[0].Identifiers)
			}
		})
	}
}

func TestParseNmap_TLS(t *testing.T) {
	t.Parallel()

	nmap := model.Nmap{
		Address: "127.0.0.1",
		Status:  "up",
		Ports: []model.NmapPort{
			{
				ID:       40645,
				State:    "open",
				Protocol: "tcp",
				Service: model.NmapService{
					Name:    "ssl",
					Product: "",
					Version: "",
				},
				Ciphers: []model.SSLEnumCiphers{
					{
						Name: "TLSv1.2",
						Ciphers: []string{
							"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
							"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
							"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
							"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
							"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						},
					},
					{
						Name: "TLSv1.3",
						Ciphers: []string{
							"TLS_AKE_WITH_AES_128_GCM_SHA256",
							"TLS_AKE_WITH_AES_256_GCM_SHA384",
							"TLS_AKE_WITH_CHACHA20_POLY1305_SHA256",
						},
					},
				},
				TLSCerts: []model.Finding{
					{
						Raw: []byte(`-----BEGIN CERTIFICATE-----
MIICywxhaWxob3N0MB4XDTIxMTAzMjA0NzU5WhcNMjUxMTAzMjE0NzU5WjAUMRIw
EAYDVQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQCYq+6pXGEi5wM1OV8bW1PqP6XVn+FJP1BCXyJZ8p+1zHpPzwE56qtD4iJJaBHU
Co2rOUJ3A14w3OrVDcrwZZVFYCY2XkZQn6Rakv6yAt+Paq9y4DXJYibdrnWTeSkk
zhutKktBE0fH4hbrEvGsrQzOW4Lcm6JJAzEhkqZ4eR2pOvXQEvFmGrIgaf0qr2Ah
qBj0avw/bWb/7xOtAgMBAAGjVTBTMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK
BggrBgEFBQcDATAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDQYJKoZIhvcNAQELBQADggEBAHJuT+AzIpH6lKm3Qx5qW8Y1ZX8j4Mzan5oJz119tRKmsTh
ZywEBdyQftgJgkOezwq7xkp/X2bSmkfa5Ah7E+Adb8zeXzutlVQ+CoT6C/QQ2ulPXwkWF7+1IokjGR0DdIx1zHwbpxsIiNjapPggLHBg6zXzS8V+T7SnZ3ISJs6+HHzm9UojfQtaaIcvlB3fmcRV2oHQxLvwDOGReiy
lPqvoNaAu5xFgDfb1+0nYr6oGvlUti6WCturiDdEKwG/lEW4oCU=
-----END CERTIFICATE-----`),
						Location: "127.0.0.1:40645",
						Source:   "nmap",
					},
				},
				SSHHostKeys: nil,
				Scripts:     nil,
			},
		},
	}

	compos := cdxprops.ParseNmap(t.Context(), nmap)
	require.Len(t, compos, 3)

	const expectedTLS12 = `
{
  "bom-ref": "crypto/protocol/tls@1.2",
  "type": "cryptographic-asset",
  "name": "TLSv1.2",
  "cryptoProperties": {
    "assetType": "protocol",
    "protocolProperties": {
      "type": "tls",
      "version": "1.2",
      "cipherSuites": [
        {
          "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
          "algorithms": [
            "crypto/algorithm/ecdh-curve25519@1.3.132.1.12",
            "crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1",
            "crypto/algorithm/aes-128-gcm@2.16.840.1.101.3.4.1.6",
            "crypto/algorithm/sha-256@2.16.840.1.101.3.4.2.1"
          ],
          "identifiers": [
            "0xC0",
            "0x2F"
          ]
        },
        {
          "name": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
          "algorithms": [
            "crypto/algorithm/ecdh-curve25519@1.3.132.1.12",
            "crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1",
            "crypto/algorithm/chacha20-poly1305@ietf-rfc8439",
            "crypto/algorithm/sha-256@2.16.840.1.101.3.4.2.1"
          ],
          "identifiers": [
            "0xCC",
            "0xA8"
          ]
        },
        {
          "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
          "algorithms": [
            "crypto/algorithm/ecdh-curve25519@1.3.132.1.12",
            "crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1",
            "crypto/algorithm/aes-256-gcm@2.16.840.1.101.3.4.1.46",
            "crypto/algorithm/sha-384@2.16.840.1.101.3.4.2.2"
          ],
          "identifiers": [
            "0xC0",
            "0x30"
          ]
        },
        {
          "name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
          "algorithms": [
            "crypto/algorithm/ecdh-curve25519@1.3.132.1.12",
            "crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1",
            "crypto/algorithm/aes-128-cbc@2.16.840.1.101.3.4.1.2",
            "crypto/algorithm/sha-1@1.3.14.3.2.26"
          ],
          "identifiers": [
            "0xC0",
            "0x13"
          ]
        },
        {
          "name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
          "algorithms": [
            "crypto/algorithm/ecdh-curve25519@1.3.132.1.12",
            "crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1",
            "crypto/algorithm/aes-256-cbc@2.16.840.1.101.3.4.1.42",
            "crypto/algorithm/sha-1@1.3.14.3.2.26"
          ],
          "identifiers": [
            "0xC0",
            "0x14"
          ]
        }
      ]
    }
  }
}
`

	const expectedTLS13 = `
{
  "bom-ref": "crypto/protocol/tls@1.3",
  "type": "cryptographic-asset",
  "name": "TLSv1.3",
  "cryptoProperties": {
    "assetType": "protocol",
    "protocolProperties": {
      "type": "tls",
      "version": "1.3",
      "cipherSuites": [
        {
          "name": "TLS_AKE_WITH_AES_128_GCM_SHA256",
          "algorithms": [
            "crypto/algorithm/aes-128-gcm@2.16.840.1.101.3.4.1.6",
            "crypto/algorithm/sha-256@2.16.840.1.101.3.4.2.1"
          ],
          "identifiers": [
            "0x13",
            "0x1"
          ]
        },
        {
          "name": "TLS_AKE_WITH_AES_256_GCM_SHA384",
          "algorithms": [
            "crypto/algorithm/aes-256-gcm@2.16.840.1.101.3.4.1.46",
            "crypto/algorithm/sha-384@2.16.840.1.101.3.4.2.2"
          ],
          "identifiers": [
            "0x13",
            "0x2"
          ]
        },
        {
          "name": "TLS_AKE_WITH_CHACHA20_POLY1305_SHA256",
          "algorithms": [
            "crypto/algorithm/chacha20-poly1305@ietf-rfc8439",
            "crypto/algorithm/sha-256@2.16.840.1.101.3.4.2.1"
          ],
          "identifiers": [
            "0x13",
            "0x3"
          ]
        }
      ]
    }
  }
}
`

	testCases := []struct {
		scenario string
		given    cdx.Component
		then     string
	}{
		{
			scenario: "tls12",
			given:    compos[0],
			then:     expectedTLS12,
		},
		{
			scenario: "tls13",
			given:    compos[1],
			then:     expectedTLS13,
		},
		{
			scenario: "cert",
			given:    compos[2],
			then:     `{"description":"TODO parse TLS cert from nmap", "name":"", "scope":"127.0.0.1:40645", "type":""}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			require.NoError(t, enc.Encode(tc.given))
			require.JSONEq(t, tc.then, buf.String())
		})
	}
}
