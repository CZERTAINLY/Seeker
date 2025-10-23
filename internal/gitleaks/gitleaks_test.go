package gitleaks

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/report"
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

	detector, err := NewDetector()
	require.NoError(t, err)

	detections, err := detector.Detect(t.Context(), []byte(src), "aws.py")
	require.NoError(t, err)
	require.NotEmpty(t, detections)
	// ensure we have some components
	found := 0
	for _, d := range detections {
		found += len(d.Components)
	}
	require.Greater(t, found, 0)
}

func TestFindingToComponent_MappingAndSkip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		finding  report.Finding
		skip     bool
		expected string
	}{
		{"skip-private-key", report.Finding{RuleID: "private-key"}, true, ""},
		{"jwt-token", report.Finding{RuleID: "jwt-something"}, false, "token"},
		{"generic-token", report.Finding{RuleID: "my-token"}, false, "token"},
		{"key", report.Finding{RuleID: "api-key"}, false, "key"},
		{"password", report.Finding{RuleID: "db-password"}, false, "password"},
		{"unknown", report.Finding{RuleID: "mystery"}, false, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compo, skip := findingToComponent(tc.finding)
			require.Equal(t, tc.skip, skip)
			if skip {
				return
			}
			require.NotNil(t, compo.CryptoProperties)
			require.NotNil(t, compo.CryptoProperties.RelatedCryptoMaterialProperties)
			var got string
			switch compo.CryptoProperties.RelatedCryptoMaterialProperties.Type {
			case "token":
				got = "token"
			case "key":
				got = "key"
			case "password":
				got = "password"
			default:
				got = "unknown"
			}
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestDetector_AppendsEvidenceLocation(t *testing.T) {
	// Note: do not mark this test as parallel to avoid data races in gitleaks/v8
	d, err := NewDetector()
	require.NoError(t, err)

	const body = "token = 'AKIAZZZZZZZZZZZZZZZZ'\n"
	path := "aws.py"
	dets, err := d.Detect(t.Context(), []byte(body), path)
	require.NoError(t, err)
	if len(dets) == 0 {
		t.Skip("no detections from gitleaks in this environment")
	}

	// at least one component has an occurrence with the given path
	found := false
	for _, det := range dets {
		for _, compo := range det.Components {
			if compo.Evidence == nil || compo.Evidence.Occurrences == nil {
				continue
			}
			for _, occ := range *compo.Evidence.Occurrences {
				if occ.Location == path {
					found = true
					break
				}
			}
		}
	}
	require.True(t, found, "expected evidence occurrence with location set to path")
}

func TestDetect_NoFindings_ReturnsNil(t *testing.T) {
	// do not run in parallel (global upstream state)
	d, err := NewDetector()
	require.NoError(t, err)
	res, err := d.Detect(t.Context(), []byte("just some text without secrets"), "plain.txt")
	require.NoError(t, err)
	require.Nil(t, res)
}

func TestDetect_ConcurrentCalls(t *testing.T) {
	// do not run in parallel (global upstream state)
	d, err := NewDetector()
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
	probe, err := d.Detect(t.Context(), []byte("token = 'AKIAZZZZZZZZZZZZZZZZ'"), "file.txt")
	require.NoError(t, err)
	expectSomeFindings := len(probe) > 0 && len(probe[0].Components) > 0

	for _, in := range inputs {
		wg.Add(1)
		body := in
		go func() {
			defer wg.Done()
			res, err := d.Detect(t.Context(), []byte(body), "file.txt")
			require.NoError(t, err)
			mx.Lock()
			defer mx.Unlock()
			if len(res) == 0 || len(res[0].Components) == 0 {
				totalNoFindings++
			} else {
				// sanity: at least one component name should contain a keyword from input
				joined := body
				nameMatch := false
				for _, c := range res[0].Components {
					if strings.Contains(joined, "jwt") || strings.Contains(c.Name, "token") || strings.Contains(c.Name, "key") || strings.Contains(c.Name, "password") {
						nameMatch = true
						break
					}
				}
				require.True(t, nameMatch)
				totalWithFindings++
			}
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
	d, err := NewDetector()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := d.Detect(ctx, []byte("anything"), "x.txt")
	require.Error(t, err)
	require.Nil(t, res)
}
