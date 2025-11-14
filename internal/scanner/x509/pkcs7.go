package x509

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"time"

	"github.com/smallstep/pkcs7"
)

// OID prefix: 1.2.840.113549.1.7 (PKCS#7/CMS ContentInfo contentType family)
var oidPkcs7Prefix = []int{1, 2, 840, 113549, 1, 7}

func oidHasPrefix(oid asn1.ObjectIdentifier, prefix []int) bool {
	if len(oid) < len(prefix) {
		return false
	}
	for i := range prefix {
		if oid[i] != prefix[i] {
			return false
		}
	}
	return true
}

// Quick DER sniff: ContentInfo with contentType under 1.2.840.113549.1.7.*
// Be permissive: tolerate BER-ish lengths and fall back to a byte scan if needed.
func sniffPKCS7DER(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	// Heuristic fast path: scan first 2KB for the OID bytes
	const maxScan = 2048
	prefixBytes := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07}
	window := b
	if len(window) > maxScan {
		window = window[:maxScan]
	}
	if bytes.Contains(window, prefixBytes) {
		return true
	}

	// Structured path
	var top asn1.RawValue
	if _, err := asn1.Unmarshal(b, &top); err != nil {
		return false
	}
	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
	}
	var ci contentInfo
	if _, err := asn1.Unmarshal(top.Bytes, &ci); err != nil {
		return false
	}
	return oidHasPrefix(ci.ContentType, oidPkcs7Prefix)
}

// Make the parser optionally "permissive" (e.g., for PEM blocks explicitly labeled PKCS7/CMS)
func ParsePKCS7Safe(ctx context.Context, b []byte, permissive bool) []*x509.Certificate {
	// Only gate by sniff when not in permissive mode
	if !permissive && !sniffPKCS7DER(b) {
		return nil
	}

	type result struct{ certs []*x509.Certificate }
	ch := make(chan result, 1)

	timeoutCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	go func() {
		defer func() { _ = recover() }()
		p7, err := pkcs7.Parse(b) // github.com/smallstep/pkcs7 (supports degenerate signedData)
		if err != nil || len(p7.Certificates) == 0 {
			ch <- result{nil}
			return
		}
		out := make([]*x509.Certificate, len(p7.Certificates))
		copy(out, p7.Certificates)
		ch <- result{out}
	}()

	select {
	case <-timeoutCtx.Done():
		return nil
	case r := <-ch:
		return r.certs
	}
}
