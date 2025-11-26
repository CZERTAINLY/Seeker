package cdxprops_test

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops"
	"github.com/CZERTAINLY/Seeker/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

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
				TLSCerts: []model.CertHit{
					pemHit{
						Raw: []byte(`-----BEGIN CERTIFICATE-----
MIIF7zCCA9egAwIBAgIUCMqEjHI4T6kthdMJu78jyoU0t7AwDQYJKoZIhvcNAQEL
BQAwgYYxCzAJBgNVBAYTAlhYMRIwEAYDVQQIDAlTdGF0ZU5hbWUxETAPBgNVBAcM
CENpdHlOYW1lMRQwEgYDVQQKDAtDb21wYW55TmFtZTEbMBkGA1UECwwSQ29tcGFu
eVNlY3Rpb25OYW1lMR0wGwYDVQQDDBRDb21tb25OYW1lT3JIb3N0bmFtZTAeFw0y
NTEwMjAxMDE2MDdaFw0zNTEwMTgxMDE2MDdaMIGGMQswCQYDVQQGEwJYWDESMBAG
A1UECAwJU3RhdGVOYW1lMREwDwYDVQQHDAhDaXR5TmFtZTEUMBIGA1UECgwLQ29t
cGFueU5hbWUxGzAZBgNVBAsMEkNvbXBhbnlTZWN0aW9uTmFtZTEdMBsGA1UEAwwU
Q29tbW9uTmFtZU9ySG9zdG5hbWUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQDHpyqMDyC06hAoKjTmXXzq3m9vBqXjzdGA21mTORmnmrZQO18W9SD1dq8N
aAwjVAEDJcP2b5iwFTuBbwWJfKGWwNo3d68pakwnLdgWxtmKmGPkvBPSNCz1Nwa0
bSty06lBUOs9kL8z5uKY23bi4dgyeO9cKJdkfwSVtxBT4l4c12PN1ymUlEp2Z8u5
PEElg1x4yIxKtXqfw45/cClwANdvK5wHDrVQ8tz1nRuEU43K67l4tqTklY+JDogB
3RiMfXHIpZ4Fk5XWB9/iyiUrYh53ojqchjAF+isNMuOCsfpl46hYlzcndL2Zm5dN
I+A9fcWqzPT7a5kc13rkbyglCM1mazcl3bQFpoY9Y0Pabysr/nVychBA+9UOn9AA
VBd1eCvmT4r8gWXRaJqgk051pyeHmp3toEhryRS2ONv2LJ9ifkvyBKHutWjLjugP
MvgLAQjiSv1prAilsg2d6gM7Eli+OY6fpavelI1wG4b87mEhU1nTmLtM4d90jwNv
iUk0sEGo2lMuIXP4epHifXWMG5/gUUcpuuEJAt1PkLYD6L1IbWFuRblR6MnenbcN
c+QzUd0AcLJKKYgqPMxgPW0Jq+KPDC2eMOSQCD2KVOLsaJDnWbC2iyQYl6xcIhcp
sLvRgsSuJj3cOVEulVIn18EJvsK1EtPNjs6vgDzulTziVQBuRwIDAQABo1MwUTAd
BgNVHQ4EFgQUPQ5bXWzI8hql/z9uSFfuM0WmZuQwHwYDVR0jBBgwFoAUPQ5bXWzI
8hql/z9uSFfuM0WmZuQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AgEAHxfi/WrErM+UbIjmWJe3V1r63jsdCve6syr5aGN0aXDanzlDUAzB5t/httG0
TQHh8gP4O0nHgtm368v1uZ0NaYHOGbvV+j0WQ4ulhJcBjYhobRU6XYM2sIrgJkLo
jUmz2b7Y1Q8fBz3G4g1puu0s1AoRvZVwsVzQ3M6AMjLgEnDbQt89kTM8EnReXYq4
6ar3ksiJMapmhuiGatVqQl6wyCtl9Ef6Tl8zaDyBvziDsl7hiN+FQxQFz8YgWWr7
L/rNkuIid4uj/209vJm0BJMHjOx4abaTFZhdnTtTONvjD48LsKExFvdV0CWC5mnI
lJ68kNDyOS59bdMqsPC9erFcheoAoT04/8rjXwTwXwEUyUEpuQXvctTGEAV19HzZ
nKJKqXthLCxsTPteGzAexFPmMdOiZiCGMGIQQk9tirz4E1YEsLYMMNvre6LByuEp
VR9gCh0N/FxU2+/HR2hMJLIbIMdQ1YlxVdsR3e3/RKUGnpwB0LqH2vQhg/WFFawO
2013tnAGd5FCO3lrCwwo7cwvci/IyMex3GmZXyFNdddK/fKmdVJDr/k3O7QhuW2I
U7/C9UWr2GEk6inRCF9unCHXUzQNLg56Mf0I8dw8PDJ3QbVywN0csSJxGqcGRoyM
YhdzwN34rxXHelPfnN3lpV674QQnbYoVDDpfcZf+ZgkbvOk=
-----END CERTIFICATE-----
`),
						Location: "127.0.0.1:40645",
						Source:   "NMAP",
					}.CertHit(t),
				},
				SSHHostKeys: nil,
				Scripts:     nil,
			},
		},
	}

	c := cdxprops.NewConverter()
	d := c.Nmap(t.Context(), nmap)
	require.NotNil(t, d)
	compos := d.Components
	require.Len(t, compos, 7)

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
			then:     `{"bom-ref":"crypto/certificate/CommonNameOrHostname@sha256:0c06b74cdea91e45929b8b94e107ed9201732158be6381fa87ee0af9a830423f","type":"cryptographic-asset","name":"CommonNameOrHostname","version":"50188223309792639209962727766352873045328443312","description":"Public key (x509)","hashes":[{"alg":"SHA-256","content":"0c06b74cdea91e45929b8b94e107ed9201732158be6381fa87ee0af9a830423f"},{"alg":"SHA-1","content":"3e0450b54b0d72093a0fcb9bd0280653b6ea90b9"}],"properties":[{"name":"czertainly:component:certificate:source_format","value":"NMAP"},{"name":"czertainly:component:certificate:base64_content","value":"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"},{"name":"czertainly:component:certificate:version","value":"3"},{"name":"czertainly:component:certificate:issuer","value":"CN=CommonNameOrHostname,OU=CompanySectionName,O=CompanyName,L=CityName,ST=StateName,C=XX"},{"name":"czertainly:component:certificate:subject","value":"CN=CommonNameOrHostname,OU=CompanySectionName,O=CompanyName,L=CityName,ST=StateName,C=XX"},{"name":"czertainly:component:certificate:basic_constraints_valid","value":"true"},{"name":"czertainly:component:certificate:is_ca","value":"true"},{"name":"czertainly:component:certificate:subject_key_id","value":"3d0e5b5d6cc8f21aa5ff3f6e4857ee3345a666e4"},{"name":"czertainly:component:certificate:authority_key_id","value":"3d0e5b5d6cc8f21aa5ff3f6e4857ee3345a666e4"},{"name":"czertainly:component:certificate:extension:2.5.29.14","value":"critical=false,value=04143d0e5b5d6cc8f21aa5ff3f6e4857ee3345a666e4"},{"name":"czertainly:component:certificate:extension:2.5.29.35","value":"critical=false,value=301680143d0e5b5d6cc8f21aa5ff3f6e4857ee3345a666e4"},{"name":"czertainly:component:certificate:extension:2.5.29.19","value":"critical=true,value=30030101ff"}],"cryptoProperties":{"assetType":"certificate","certificateProperties":{"subjectName":"CN=CommonNameOrHostname,OU=CompanySectionName,O=CompanyName,L=CityName,ST=StateName,C=XX","issuerName":"CN=CommonNameOrHostname,OU=CompanySectionName,O=CompanyName,L=CityName,ST=StateName,C=XX","notValidBefore":"2025-10-20T10:16:07Z","notValidAfter":"2035-10-18T10:16:07Z","signatureAlgorithmRef":"crypto/algorithm/sha-256-rsa@sha256:05764cb750e4fc51757f337e676614311ee96c8445f999930661a8106d4c2779","subjectPublicKeyRef":"crypto/algorithm/rsa-4096@sha256:9a9cf9242c15f022bd5d2ee8c999f8e1f9809a48d4170b16a33d9d96c463ee29","certificateFormat":"X.509","certificateExtension":".1:40645"},"relatedCryptoMaterialProperties":{"id":"50188223309792639209962727766352873045328443312","state":"active","creationDate":"2025-10-20T10:16:07Z","activationDate":"2025-10-20T10:16:07Z","expirationDate":"2035-10-18T10:16:07Z"}}}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			require.NoError(t, enc.Encode(tc.given))
			t.Logf("%s", buf.String())
			require.JSONEq(t, tc.then, buf.String())
		})
	}
}

type pemHit struct {
	Raw      []byte
	Source   string
	Location string
}

func (h pemHit) CertHit(t *testing.T) model.CertHit {
	t.Helper()
	block, _ := pem.Decode(h.Raw)
	require.NotNil(t, block, "failed to decode PEM block")
	require.Equal(t, "CERTIFICATE", block.Type)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return model.CertHit{
		Cert:     cert,
		Source:   h.Source,
		Location: h.Location,
	}
}
