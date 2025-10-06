package service_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/service"
	"github.com/stretchr/testify/require"
)

func TestRunner(t *testing.T) {
	t.Parallel()
	yes, err := exec.LookPath("yes")
	if err != nil {
		t.Skipf("skipped, binary yes not available: %v", err)
	}

	runner := service.NewRunner()
	t.Cleanup(runner.Close)
	t.Run("not yet started", func(t *testing.T) {
		res := runner.LastResult()
		require.ErrorIs(t, res.Err, service.ErrScanNotStarted)
	})

	cmd := service.Command{
		Path:    yes,
		Args:    []string{"golang"},
		Env:     []string{"LC_ALL=C"},
		Timeout: 100 * time.Millisecond,
	}
	ctx := t.Context()

	t.Run("start", func(t *testing.T) {
		err = runner.Start(ctx, cmd, nil)
		require.NoError(t, err)
		res := runner.LastResult()
		require.NoError(t, res.Err)
	})
	t.Run("in progress", func(t *testing.T) {
		err = runner.Start(ctx, cmd, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, service.ErrScanInProgress)
	})
	t.Run("wait", func(t *testing.T) {
		res := <-runner.ResultsChan()
		require.Equal(t, yes, res.Path)
		require.Equal(t, []string{"golang"}, res.Args)
		require.NotZero(t, res.Started)
		require.NotZero(t, res.Stopped)
		require.GreaterOrEqual(t, res.Stopped.Sub(res.Started), 100*time.Millisecond)
		require.Error(t, res.Err)
		var exitErr *exec.ExitError
		require.ErrorAs(t, res.Err, &exitErr)

		require.Greater(t, res.Stdout.Len(), 1024)
		require.True(t, strings.HasPrefix(
			string(res.Stdout.Bytes()[:256]),
			"golang\ngolang\n",
		))
	})
	t.Run("exec error", func(t *testing.T) {
		noCmd := service.Command{
			Path: "does not exist",
		}
		err := runner.Start(ctx, noCmd, nil)
		require.Error(t, err)
		var execErr *exec.Error
		require.ErrorAs(t, err, &execErr)
		require.Equal(t, noCmd.Path, execErr.Name)
		require.EqualError(t, execErr.Err, "executable file not found in $PATH")
	})
}

func TestStderr(t *testing.T) {
	t.Parallel()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("skipped, binary sh not available: %v", err)
	}

	cmd := service.Command{
		Path: sh,
		Args: []string{"-c", "echo stdout; echo -e 1>&2 'stderr\nstderr'"},
	}

	var stderr []string
	handle := func(_ context.Context, line string) {
		stderr = append(stderr, line)
	}

	runner := service.NewRunner()
	t.Cleanup(runner.Close)
	err = runner.Start(t.Context(), cmd, handle)
	require.NoError(t, err)
	res := <-runner.ResultsChan()
	require.Equal(t, "stdout\n", res.Stdout.String())
	require.Equal(t, []string{"stderr", "stderr"}, stderr)
}
