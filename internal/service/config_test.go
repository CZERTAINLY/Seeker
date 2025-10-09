package service_test

import (
	"strings"
	"testing"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/service"
	"github.com/spf13/viper"

	"github.com/stretchr/testify/require"
)

const alphaConfig = `
alpha:
  svc:
    command:
      path: seeker
      args:
        - --verbose
        - alpha
        - scan
      timeout: "15s"
      env:
        HOME: $HOME
        GODEBUG: "tlsssha=1,x509negativeserial=1"
    scan_each: "20s"
`

func TestParseConfig(t *testing.T) {
	// can't be parallel as touches the viper package
	viper.SetConfigType("yaml")
	err := viper.ReadConfig(strings.NewReader(alphaConfig))
	require.NoError(t, err)
	cfg, err := service.ParseConfig("alpha.svc")
	require.NoError(t, err)
	t.Logf("got: %+v", cfg)

	require.Equal(t, "seeker", cfg.Command.Path)
	require.Contains(t, cfg.Command.Env["godebug"], "tlsssha=1")
	require.Equal(t, 20*time.Second, cfg.ScanEach)

	t.Run("cmd", func(t *testing.T) {
		cmd := cfg.Cmd()
		require.Equal(t, cfg.Command.Path, cmd.Path)
	})
}
