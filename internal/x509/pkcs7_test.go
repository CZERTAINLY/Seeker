package x509_test

import (
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/model"
	czX509 "github.com/CZERTAINLY/Seeker/internal/x509"
	"github.com/stretchr/testify/require"
)

func Test_PKCS7_InvalidData(t *testing.T) {
	t.Parallel()
	
	// Test PKCS7 parsing with various invalid data to improve coverage
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x30, 0x82}},
		{"invalid ASN.1", []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{"contains PKCS7 OID bytes but invalid structure", []byte{
			0x30, 0x82, 0x01, 0x23, // SEQUENCE 
			0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, // OID bytes
			0xFF, 0xFF, // invalid continuation
		}},
		// This one will test the oidHasPrefix function by creating valid ASN.1 with wrong OID
		{"valid ASN.1 with wrong OID", []byte{
			0x30, 0x20, // SEQUENCE, length 32
			0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, // OID 1.2.840.113549.1.1 (RSA, not PKCS7)
			0x04, 0x13, // OCTET STRING, length 19
			0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x20, 0x54, 0x65, 0x73, 0x74, // "Hello, World! Test"
		}},
		// This one will also exercise oidHasPrefix with a shorter OID
		{"valid ASN.1 with short OID", []byte{
			0x30, 0x10, // SEQUENCE, length 16
			0x06, 0x03, 0x2A, 0x86, 0x48, // OID 1.2.840 (shorter than PKCS7 prefix)
			0x04, 0x09, // OCTET STRING, length 9
			0x54, 0x65, 0x73, 0x74, 0x20, 0x64, 0x61, 0x74, 0x61, // "Test data"
		}},
	}
	
	var d czX509.Detector
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := d.Detect(t.Context(), tt.data, "testpath")
			require.Error(t, err)
			require.ErrorIs(t, err, model.ErrNoMatch)
		})
	}
}

func Test_OidHasPrefix(t *testing.T) {
	t.Parallel()
	
	// Test oidHasPrefix function to improve coverage
	// This is a unit test for the internal oidHasPrefix function
	// We need to use reflection or add it as an exposed function for testing
	
	// Create test PKCS7 data that would exercise the sniffing
	der, _, _ := genSelfSignedCert(t)
	
	// Try with malformed PKCS7 data to exercise the oidHasPrefix path
	// This is a bit indirect but will exercise the code paths
	badData := []byte{0x30, 0x82, 0x01, 0x23} // partial ASN.1 SEQUENCE
	
	var d czX509.Detector
	_, err := d.Detect(t.Context(), badData, "testpath")
	require.Error(t, err) // Should fail due to no match
	require.ErrorIs(t, err, model.ErrNoMatch)
	
	// Test with real certificate that might go through DER detection
	_, err = d.Detect(t.Context(), der, "testpath")
	require.NoError(t, err) // Should succeed
}