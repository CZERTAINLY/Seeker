package netscan_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"
)

var (
	ipv4 netip.AddrPort
	ipv6 netip.AddrPort
)

func TestMain(m *testing.M) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("generate self-signed certificate: %v", err)
	}

	// Listener on IPv4
	ln4, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		log.Fatalf("listen ipv4: %v", err)
	}
	defer func() {
		_ = ln4.Close()
	}()

	// Listener on IPv6
	ln6, err := tls.Listen("tcp6", "[::1]:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		log.Fatalf("listen ipv6: %v", err)
	}
	defer func() {
		_ = ln6.Close()
	}()

	srv4 := tlsServer(ln4, cert, "ipv4: ok")
	defer srv4.Close()

	srv6 := tlsServer(ln6, cert, "ipv6: ok")
	defer srv6.Close()

	// store ipv4 and ipv6 addresses of the test servers
	ipv4 = netip.MustParseAddrPort(srv4.Listener.Addr().String())
	ipv6 = netip.MustParseAddrPort(srv6.Listener.Addr().String())

	ret := m.Run()
	os.Exit(ret)
}

func tlsServer(ln net.Listener, cert tls.Certificate, msg string) *httptest.Server {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(msg))
		if err != nil {
			panic(err)
		}
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Listener = ln
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	return server
}

// generateSelfSignedCert makes a temporary self-signed TLS cert.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	return cert, nil
}
