package service_test

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/CZERTAINLY/Seeker/internal/service"

	"github.com/stretchr/testify/require"
)

func TestSupervisor(t *testing.T) {
	t.Parallel()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("skipped, binary sh not available: %v", err)
	}

	cmd := service.Command{
		Path:    sh,
		Args:    []string{"-c", "echo stdout;"},
		Timeout: 90 * time.Millisecond,
	}

	t.Run("timer", func(t *testing.T) {
		const config = `
version: 0

service:
    mode: timer
    every: "* * * * * *"
`
		cfg, err := model.LoadConfig(strings.NewReader(config))
		require.NoError(t, err)
		var buf bytes.Buffer
		u := service.NewWriteUploader(&buf)
		supervisor, err := service.NewSupervisor(t.Context(), cfg.Service, t.Name()+".yaml")
		require.NoError(t, err)
		supervisor = supervisor.WithCmdUploaders(t.Context(), cmd, u)

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		t.Cleanup(cancel)

		var g sync.WaitGroup
		g.Go(func() {
			err := supervisor.Do(ctx)
			require.NoError(t, err)
		})

		g.Wait()
		stdout := buf.String()
		require.NotEmpty(t, stdout)
		require.True(t, strings.HasPrefix(stdout, "stdout\nstdout\n"))
	})

	t.Run("oneshot", func(t *testing.T) {
		const config = `
version: 0

service:
    mode: manual
`
		cfg, err := model.LoadConfig(strings.NewReader(config))
		require.NoError(t, err)
		var buf bytes.Buffer
		u := service.NewWriteUploader(&buf)
		supervisor, err := service.NewSupervisor(t.Context(), cfg.Service, t.Name()+".yaml")
		require.NoError(t, err)
		supervisor = supervisor.WithCmdUploaders(t.Context(), cmd, u)
		err = supervisor.Do(t.Context())
		require.NoError(t, err)
		stdout := buf.String()
		require.NotEmpty(t, stdout)
		require.Equal(t, "stdout\n", stdout)
	})
}

func TestSupervisorFromConfig(t *testing.T) {
	cfg := model.Config{
		Service: model.Service{
			Verbose: true,
		},
	}
	supervisor, err := service.NewSupervisor(t.Context(), cfg.Service, "seeker.yaml")
	require.NoError(t, err)
	require.NotEmpty(t, supervisor)
}

func TestOSRootUploader(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	u, err := service.NewOSRootUploader(dir)
	require.NoError(t, err)
	err = u.Upload(t.Context(), []byte("raw"))
	require.NoError(t, err)
}
