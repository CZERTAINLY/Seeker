package x509_test

import (
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/model"
	czX509 "github.com/CZERTAINLY/Seeker/internal/x509"
	"github.com/stretchr/testify/require"
)

func Test_Detector_Integration(t *testing.T) {
	t.Parallel()
	
	// Test main detector coordination functionality
	var d czX509.Detector
	attrs := d.LogAttrs()
	require.Len(t, attrs, 1)
	require.Equal(t, "detector", attrs[0].Key)
	require.Equal(t, "x509", attrs[0].Value.String())
}

func Test_Detector_NoMatch(t *testing.T) {
	t.Parallel()
	
	// Test that detector returns no match for invalid data
	var d czX509.Detector
	_, err := d.Detect(t.Context(), []byte("invalid data"), "testpath")
	require.Error(t, err)
	require.ErrorIs(t, err, model.ErrNoMatch)
}