package pem_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/Seeker/internal/model"
	czpem "github.com/CZERTAINLY/Seeker/internal/scanner/pem"

	"github.com/stretchr/testify/require"
)

func TestDetector(t *testing.T) {
	type given struct {
		data   []byte
		bundle model.PEMBundle
	}

	testCases := []struct {
		scenario string
		given    func(t *testing.T) given
		then     error
	}{
		{
			scenario: "single certificate",
			given: func(t *testing.T) given {
				cert, err := cdxtest.GenSelfSignedCert()
				require.NoError(t, err)

				pemData := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Der,
				})

				return given{
					data: pemData,
					bundle: model.PEMBundle{
						Certificates: []model.CertHit{{Cert: cert.Cert, Source: "PEM", Location: "test.pem"}},
						RawBlocks: []model.PEMBlock{
							{Type: "CERTIFICATE", Order: 0, Bytes: cert.Der, Headers: map[string]string{}},
						},
						Location: "test.pem",
					},
				}
			},
			then: nil,
		},
		{
			scenario: "certificate with RSA PKCS#1 private key",
			given: func(t *testing.T) given {
				cert, err := cdxtest.GenSelfSignedCert()
				require.NoError(t, err)

				keyBytes := cdxtest.EncodePKCS1(cert.Key)

				var buf bytes.Buffer
				buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Der}))
				buf.Write(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}))

				return given{
					data: buf.Bytes(),
					bundle: model.PEMBundle{
						Certificates: []model.CertHit{{Cert: cert.Cert, Source: "PEM", Location: "test.pem"}},
						PrivateKeys: []model.PrivateKeyInfo{{
							Key:      cert.Key,
							Type:     "RSA",
							Source:   "PKCS1-PEM",
							Location: "test.pem",
						}},
						RawBlocks: []model.PEMBlock{
							{Type: "CERTIFICATE", Order: 0, Bytes: cert.Der, Headers: map[string]string{}},
							{Type: "RSA PRIVATE KEY", Order: 1, Bytes: keyBytes, Headers: map[string]string{}},
						},
						Location: "test.pem",
					},
				}
			},
			then: nil,
		},
		{
			scenario: "PKCS#8 private key (RSA)",
			given: func(t *testing.T) given {
				cert, err := cdxtest.GenSelfSignedCert()
				require.NoError(t, err)

				pkcs8, err := cdxtest.EncodePKCS8(cert.Key)
				require.NoError(t, err)

				pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

				return given{
					data: pemData,
					bundle: model.PEMBundle{
						PrivateKeys: []model.PrivateKeyInfo{
							{
								Key:      cert.Key,
								Type:     "RSA",
								Source:   "PKCS8-PEM",
								Location: "test.pem",
							},
						},
						RawBlocks: []model.PEMBlock{
							{Type: "PRIVATE KEY", Order: 0, Bytes: pkcs8, Headers: map[string]string{}},
						},
					},
				}
			},
			then: nil,
		},
		{
			scenario: "EC private key",
			given: func(t *testing.T) given {
				key, err := cdxtest.GenECPrivateKey()
				require.NoError(t, err)

				der, err := cdxtest.EncodeECPrivateKey(key)
				require.NoError(t, err)

				pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

				return given{
					data: pemData,
					bundle: model.PEMBundle{
						PrivateKeys: []model.PrivateKeyInfo{
							{
								Key:      key,
								Type:     "ECDSA",
								Source:   "EC-PEM",
								Location: "test.pem",
							}},
						RawBlocks: []model.PEMBlock{
							{Type: "EC PRIVATE KEY", Order: 0, Bytes: der, Headers: map[string]string{}},
						},
					},
				}
			},
			then: nil,
		},
		{
			scenario: "OpenSSH private key",
			given: func(t *testing.T) given {
				key, pemBytes, err := cdxtest.GenOpenSSHPrivateKey()
				require.NoError(t, err)

				block, _ := pem.Decode(pemBytes)
				require.NotNil(t, block)

				return given{
					data: pemBytes,
					bundle: model.PEMBundle{
						PrivateKeys: []model.PrivateKeyInfo{{
							Key:      &key,
							Type:     "Ed25519",
							Source:   "PEM",
							Location: "test.pem",
						}},
						RawBlocks: []model.PEMBlock{
							{Type: "OPENSSH PRIVATE KEY", Order: 0, Bytes: block.Bytes, Headers: map[string]string{}},
						},
					},
				}
			},
			then: nil,
		},
		{
			scenario: "certificate request",
			given: func(t *testing.T) given {
				cert, err := cdxtest.GenSelfSignedCert()
				require.NoError(t, err)

				csr, csrDER, err := cdxtest.GenCSR(cert.Key)
				require.NoError(t, err)

				pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

				return given{
					data: pemData,
					bundle: model.PEMBundle{
						CertificateRequests: []*x509.CertificateRequest{csr},
						RawBlocks: []model.PEMBlock{
							{Type: "CERTIFICATE REQUEST", Order: 0, Bytes: csrDER, Headers: map[string]string{}},
						},
					},
				}
			},
			then: nil,
		},
		{
			scenario: "public key",
			given: func(t *testing.T) given {
				cert, err := cdxtest.GenSelfSignedCert()
				require.NoError(t, err)

				pubDER, err := x509.MarshalPKIXPublicKey(&cert.Key.PublicKey)
				require.NoError(t, err)

				pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

				return given{
					data: pemData,
					bundle: model.PEMBundle{
						PublicKeys: []crypto.PublicKey{&cert.Key.PublicKey},
						RawBlocks: []model.PEMBlock{
							{Type: "PUBLIC KEY", Order: 0, Bytes: pubDER, Headers: map[string]string{}},
						},
					},
				}
			},
			then: nil,
		},
		{
			scenario: "CRL",
			given: func(t *testing.T) given {
				b := cdxtest.CertBuilder{}.
					WithKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCRLSign | x509.KeyUsageCertSign).
					WithIsCA(true)
				cert, err := b.Generate()
				require.NoError(t, err)

				crl, crlDER, err := cdxtest.GenCRL(cert.Cert, cert.Key)
				require.NoError(t, err)

				pemData := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

				return given{
					data: pemData,
					bundle: model.PEMBundle{
						CRLs: []*x509.RevocationList{crl},
						RawBlocks: []model.PEMBlock{
							{Type: "X509 CRL", Order: 0, Bytes: crlDER, Headers: map[string]string{}},
						},
					},
				}
			},
			then: nil,
		},
		{
			scenario: "certificate chain (leaf, intermediate, root)",
			given: func(t *testing.T) given {
				leaf, err := cdxtest.GenSelfSignedCert()
				require.NoError(t, err)
				intermediate, err := cdxtest.GenSelfSignedCert()
				require.NoError(t, err)
				root, err := cdxtest.GenSelfSignedCert()
				require.NoError(t, err)

				var buf bytes.Buffer
				buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Der}))
				buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate.Der}))
				buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Der}))

				return given{
					data: buf.Bytes(),
					bundle: model.PEMBundle{
						Certificates: []model.CertHit{
							{Cert: leaf.Cert, Source: "PEM", Location: "test.pem"},
							{Cert: intermediate.Cert, Source: "PEM", Location: "test.pem"},
							{Cert: root.Cert, Source: "PEM", Location: "test.pem"},
						},
						RawBlocks: []model.PEMBlock{
							{Type: "CERTIFICATE", Order: 0, Bytes: leaf.Der, Headers: map[string]string{}},
							{Type: "CERTIFICATE", Order: 1, Bytes: intermediate.Der, Headers: map[string]string{}},
							{Type: "CERTIFICATE", Order: 2, Bytes: root.Der, Headers: map[string]string{}},
						},
					},
				}
			},
			then: nil,
		},
		{
			scenario: "empty input",
			given: func(t *testing.T) given {
				return given{
					data:   []byte{},
					bundle: model.PEMBundle{},
				}
			},
			then: model.ErrNoMatch,
		},
		{
			scenario: "invalid PEM data",
			given: func(t *testing.T) given {
				return given{
					data:   []byte("not a PEM file"),
					bundle: model.PEMBundle{},
				}
			},
			then: model.ErrNoMatch,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			// Arrange
			given := tc.given(t)
			given.bundle.Location = "test.pem"

			// Act
			bundle, err := czpem.Scanner{}.Scan(t.Context(), given.data, "test.pem")

			// Assert
			if tc.then != nil {
				require.Error(t, err)
				require.Equal(t, tc.then.Error(), err.Error())
			} else {
				require.NoError(t, err)
				require.Empty(t, bundle.ParseErrors)

				for idx, pkey := range bundle.PrivateKeys {
					require.NotNil(t, pkey.Block)
					// lets not compare pointers to raw blocks
					bundle.PrivateKeys[idx].Block = nil
				}

				require.Equal(t, given.bundle, bundle)
			}
		})
	}
}
