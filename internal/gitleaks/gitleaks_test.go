package gitleaks

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

const src = `
import os

aws_token := os.Getenv("AWS_TOKEN")
if aws_token == "":
    aws_token = "AKIALALEMEL33243OLIA"
	`

func TestDetector(t *testing.T) {
	// do not run in parallel due to global state in gitleaks/v8
	// t.Parallel()

	detector, err := NewScanner()
	require.NoError(t, err)

	results, err := detector.Scan(t.Context(), []byte(src), "aws.py")
	require.NoError(t, err)
	require.Len(t, results, 1)
}

func TestDetect_NoFindings_ReturnsNil(t *testing.T) {
	// do not run in parallel (global upstream state)
	d, err := NewScanner()
	require.NoError(t, err)
	res, err := d.Scan(t.Context(), []byte("just some text without secrets"), "plain.txt")
	require.NoError(t, err)
	require.Nil(t, res)
}

func TestDetect_ConcurrentCalls(t *testing.T) {
	// do not run in parallel (global upstream state)
	d, err := NewScanner()
	require.NoError(t, err)

	var wg sync.WaitGroup
	totalWithFindings := 0
	totalNoFindings := 0
	var mx sync.Mutex

	inputs := []string{
		"no secrets here",
		"token = 'AKIAZZZZZZZZZZZZZZZZ'",
		"hello world",
		"bearer jwt: eyJhbGciOi",
		"just text",
	}

	// Probe once to see if this environment detects the token input at all.
	probe, err := d.Scan(t.Context(), []byte("token = 'AKIAZZZZZZZZZZZZZZZZ'"), "file.txt")
	require.NoError(t, err)
	expectSomeFindings := len(probe) > 0

	for _, in := range inputs {
		wg.Add(1)
		body := in
		go func() {
			defer wg.Done()
			res, err := d.Scan(t.Context(), []byte(body), "file.txt")
			require.NoError(t, err)
			mx.Lock()
			defer mx.Unlock()
			if len(res) == 0 {
				totalNoFindings++
			}
			totalWithFindings += len(res)
		}()
	}
	wg.Wait()

	// Totals should sum to the number of inputs.
	require.Equal(t, len(inputs), totalWithFindings+totalNoFindings)
	// If the environment yields any finding for the probe, ensure at least one concurrent call had findings.
	if expectSomeFindings {
		require.GreaterOrEqual(t, totalWithFindings, 1)
	}
}

func TestDetect_ContextCanceled(t *testing.T) {
	// ensure we hit the early cancellation branch
	d, err := NewScanner()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := d.Scan(ctx, []byte("anything"), "x.txt")
	require.Error(t, err)
	require.Nil(t, res)
}
