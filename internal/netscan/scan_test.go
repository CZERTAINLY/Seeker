package netscan_test

import (
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/netscan"

	"github.com/stretchr/testify/require"
)

func TestInspectTLS(t *testing.T) {
	t.Parallel()
	result4, err := netscan.InspectTLS(t.Context(), ipv4)
	require.NoError(t, err)
	require.NotZero(t, result4)

	result6, err := netscan.InspectTLS(t.Context(), ipv6)
	require.NoError(t, err)
	require.NotZero(t, result6)
}
