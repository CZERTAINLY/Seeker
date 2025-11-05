package x509_test

import (
	"testing"

	czX509 "github.com/CZERTAINLY/Seeker/internal/x509"
	"github.com/stretchr/testify/require"
)

func Test_Detector_NoMatch(t *testing.T) {
	t.Parallel()

	// Test that detector returns no match for invalid data
	var d czX509.Scanner
	hits, err := d.Scan(t.Context(), []byte("invalid data"), "testpath")
	require.NoError(t, err)
	require.Len(t, hits, 0)
}
