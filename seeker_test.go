package seeker_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/stretchr/testify/require"
)

var (
	//go:embed testing/*
	testingFS    embed.FS
	seekerPath   string
	privKeyBytes []byte
	certDER      []byte

	// tmpDir is a function used to create a tempdir
	// -test.keepdir flag says test to use os.MkdirTemp
	// default is t.TempDir, which will be cleaned up
	tmpDir func(t *testing.T) string
)

func TestMain(m *testing.M) {
	var keepTestDir bool
	flag.BoolVar(&keepTestDir, "test.keepdir", false, "use os.TempDir instead of t.TempDir to keep test artifacts")
	flag.Lookup("test.keepdir")

	flag.Parse()

	if testing.Short() {
		slog.Warn("integration tests with -short are ignored")
		os.Exit(0)
	}

	if !keepTestDir {
		tmpDir = func(t *testing.T) string {
			t.Helper()
			return t.TempDir()
		}
	} else {
		tmpDir = func(t *testing.T) string {
			t.Helper()
			dir, err := os.MkdirTemp("", t.Name()+"*")
			require.NoError(t, err)
			_, err = fmt.Fprintf(t.Output(), "TEMPDIR %s: -test.keepir used, so it won't be automatically deleted", dir)
			require.NoError(t, err)
			return dir
		}
	}

	if !isExecutable("seeker-ci") {
		slog.Error("cannot locate seeker-ci binary: run go build -race -cover -covermode=atomic -o seeker-ci ./cmd/seeker/ first")
		os.Exit(1)
	}

	var err error
	seekerPath, err = filepath.Abs("seeker-ci")
	if err != nil {
		slog.Error("can't get abspath for seeker-ci", "error", err)
		os.Exit(1)
	}
	coverDir, err := filepath.Abs("coverage")
	if err != nil {
		slog.Error("can't get value for GOCOVERDIR for seeker-ci", "error", err)
		os.Exit(1)
	}
	err = rmRfMkdirp(coverDir)
	if err != nil {
		slog.Error("can't reset GOCOVERDIR for seeker-ci", "error", err, "coverdir", coverDir)
		os.Exit(1)
	}

	err = os.Setenv("GOCOVERDIR", coverDir)
	if err != nil {
		slog.Error("can't set GOCOVERDIR env variable", "error", err)
		os.Exit(1)
	}

	privKeyBytes, certDER, err = generateRSACert()
	if err != nil {
		slog.Error("can't generate RSA certificate", "error", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func TestSeeker(t *testing.T) {
	_ = chDir(t)

	const config = `
version: 0
filesystem:
    enabled: true
    paths: 
        - .
service:
    mode: "manual"
    verbose: false
`
	creat(t, "seeker.yaml", []byte(config))
	fixture(t, "testing/leaks/aws_token.py")
	creat(t, "priv.key", privKeyBytes)
	creat(t, "pem.cert", certDER)

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, seekerPath, "run", "--config", "seeker.yaml")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		t.Logf("%s", stderr.String())
		require.NoError(t, err)
	}

	// store the $TEST_NAME json
	creat(t, t.Name()+".json", stdout.Bytes())

	dec := cdx.NewBOMDecoder(&stdout, cdx.BOMFileFormatJSON)
	bom := cdx.BOM{}
	err = dec.Decode(&bom)
	require.NoError(t, err)

	// FIXME: should be two
	require.Len(t, *bom.Components, 3)
	names := make([]string, len(*bom.Components))
	for i, compo := range *bom.Components {
		names[i] = compo.Name
	}
	require.ElementsMatch(t, []string{
		"CN=CommonNameOrHostname,OU=CompanySectionName,O=CompanyName,L=CityName,ST=StateName,C=XX",
		"",
		"aws-access-token",
	}, names)
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0111 != 0
}

func rmRfMkdirp(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to remove directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	return nil
}

func chDir(t *testing.T) string {
	t.Helper()
	tempdir := tmpDir(t)
	err := os.Chdir(tempdir)
	require.NoError(t, err)
	return tempdir
}

func creat(t *testing.T, path string, content []byte) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, f.Close())
	}()
	_, err = f.Write(content)
	require.NoError(t, err)
	err = f.Sync()
	require.NoError(t, err)
}

func fixture(t *testing.T, inPath string) string {
	t.Helper()
	b, err := testingFS.ReadFile(inPath)
	require.NoError(t, err)
	path := filepath.Base(inPath)
	creat(t, path, b)
	return path
}

func generateRSACert() (privKeyBytes []byte, certDER []byte, err error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Prepare certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"XX"},
			Province:           []string{"StateName"},
			Locality:           []string{"CityName"},
			Organization:       []string{"CompanyName"},
			OrganizationalUnit: []string{"CompanySectionName"},
			CommonName:         "CommonNameOrHostname",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years (3650 days)
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode private key to PEM
	privKeyPEM := &bytes.Buffer{}
	err = pem.Encode(privKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	// Encode certificate to PEM
	certPEM := &bytes.Buffer{}
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode certificate: %w", err)
	}

	return privKeyPEM.Bytes(), certPEM.Bytes(), nil
}
