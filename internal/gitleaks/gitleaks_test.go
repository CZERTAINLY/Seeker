package gitleaks_test

import (
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/gitleaks"
	"github.com/stretchr/testify/require"
)

const src = `
import os

aws_token := os.Getenv("AWS_TOKEN")
if aws_token == "":
    aws_token = "AKIALALEMEL33243OLIA"
	`

func TestDetector(t *testing.T) {
	t.Parallel()

	detector, err := gitleaks.NewDetector()
	require.NoError(t, err)

	detections, err := detector.Detect(t.Context(), []byte(src), "aws.py")
	require.NoError(t, err)
	require.Len(t, detections, 1)
	t.Logf("%+v", detections[0])
}
