package service_test

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

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
		Timeout: 9 * time.Millisecond,
	}

	var buf bytes.Buffer
	supervisor := service.NewSupervisor(cmd, service.NewWriteUploader(&buf))
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	var g sync.WaitGroup
	g.Go(func() { supervisor.Do(ctx) })

	for range 5 {
		supervisor.Start()
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	g.Wait()
	stdout := buf.String()
	require.NotEmpty(t, stdout)
	require.True(t, strings.HasPrefix(stdout, "stdout\nstdout\n"))
}
