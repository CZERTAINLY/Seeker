package x509_test

import (
	"testing"

	czX509 "github.com/CZERTAINLY/Seeker/internal/x509"
	"github.com/stretchr/testify/require"
)

func Test_Detector_LogAttrs(t *testing.T) {
	t.Parallel()
	var d czX509.Detector
	attrs := d.LogAttrs()
	require.Len(t, attrs, 1)
	require.Equal(t, "detector", attrs[0].Key)
	require.Equal(t, "x509", attrs[0].Value.String())
}