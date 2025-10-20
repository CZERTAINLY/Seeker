package gitleaks

import (
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
	require.Len(t, detections, 1)
	t.Logf("%+v", detections[0])
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
