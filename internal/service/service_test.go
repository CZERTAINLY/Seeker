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

	t.Run("service", func(t *testing.T) {
		var buf bytes.Buffer
		supervisor := service.NewSupervisor(cmd, service.NewWriteUploader(&buf))
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		var g sync.WaitGroup
		g.Go(func() {
			err := supervisor.Do(ctx)
			require.NoError(t, err)
		})

		for range 5 {
			supervisor.Start()
			time.Sleep(100 * time.Millisecond)
		}

		cancel()
		g.Wait()
		stdout := buf.String()
		require.NotEmpty(t, stdout)
		require.True(t, strings.HasPrefix(stdout, "stdout\nstdout\n"))
	})

	t.Run("oneshot", func(t *testing.T) {
		var buf bytes.Buffer
		supervisor := service.NewSupervisor(cmd, service.NewWriteUploader(&buf)).SetOneshot(true)
		err := supervisor.Do(t.Context())
		require.NoError(t, err)
		stdout := buf.String()
		require.NotEmpty(t, stdout)
		require.Equal(t, "stdout\n", stdout)
	})
}

func TestSupervisorFromConfig(t *testing.T) {
	cfg := model.Config{
		Version: 0,
		Service: model.Service{
			Verbose: true,
		},
	}
	supervisor, err := service.SupervisorFromConfig(t.Context(), cfg.Service, "seeker.yaml")
	require.NoError(t, err)
	require.NotEmpty(t, supervisor)
}
