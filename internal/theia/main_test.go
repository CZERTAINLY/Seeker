package theia_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

type certificates struct {
	certificate   []byte
	privateKey    []byte // pkcs8
	ecPrivateKEy  []byte // ec
	rsaPrivateKey []byte // pkcs1
	publicKey     []byte // pkix
	sshPrivateKey []byte // (golang.org/x/crypto/ssh).ParseRawPrivateKey
	pkcs7         []byte
}

var (
	pems certificates
)

func TestMain(m *testing.M) {
	var err error
	pems, err = generateSelfSignedCert()
	if err != nil {
		log.Fatal(err)
	}

	ret := m.Run()
	os.Exit(ret)
}

func generateSelfSignedCert() (certificates, error) {
	privKeyRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return certificates{}, err
	}

	privKeyECDSA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return certificates{}, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,

		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}

	// Self-sign the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKeyRSA.PublicKey, privKeyRSA)
	if err != nil {
		return certificates{}, err
	}

	// pkcs8 private key
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privKeyRSA)
	if err != nil {
		return certificates{}, err
	}

	// ec private key
	ecBytes, err := x509.MarshalECPrivateKey(privKeyECDSA)
	if err != nil {
		return certificates{}, err
	}

	pkixBytes, err := x509.MarshalPKIXPublicKey(&privKeyECDSA.PublicKey)
	if err != nil {
		return certificates{}, err
	}

	// Encode cert and key to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKeyRSA)})
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "EX PRIVATE KEY", Bytes: ecBytes})
	pkixPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixBytes})
	sshPEM := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: pkcs8Bytes})

	// pkc7
	data := []byte("Hello, PKCS7!")
	signedData, err := pkcs7.NewSignedData(data)
	if err != nil {
		return certificates{}, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return certificates{}, err
	}
	err = signedData.AddSigner(cert, privKeyRSA, pkcs7.SignerInfoConfig{})
	if err != nil {
		return certificates{}, err
	}

	signedBytes, err := signedData.Finish()
	if err != nil {
		return certificates{}, err
	}

	pkcs7PEM := pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: signedBytes})

	return certificates{
		certificate:   certPEM,
		privateKey:    pkcs8PEM,
		ecPrivateKEy:  ecPEM,
		rsaPrivateKey: keyPEM,
		publicKey:     pkixPEM,
		sshPrivateKey: sshPEM,
		pkcs7:         pkcs7PEM,
	}, nil
}
