package scan_test

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/CZERTAINLY/Seeker/internal/scan"
	"github.com/CZERTAINLY/Seeker/internal/walk"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestScanner_Do(t *testing.T) {
	t.Parallel()

	root := fstest.MapFS{
		"is-script": &fstest.MapFile{
			Data:    []byte("#!/bin/sh"),
			Mode:    0644,
			ModTime: time.Now(),
		},
		"dir": &fstest.MapFile{
			Mode:    0755 | fs.ModeDir,
			ModTime: time.Now(),
		},
		"dir/not-a-script": &fstest.MapFile{
			Data:    []byte("not a script"),
			Mode:    0644,
			ModTime: time.Now(),
		},
	}

	isScript := NewMockDetector(t)
	noMatch := NewMockDetector(t)

	isScript.On("Detect", mock.Anything, []byte("#!/bin/sh"), "fstest::/is-script").
		Return([]model.Detection{{Path: "fstest::/is-script"}}, nil).
		Once()
	isScript.On("Detect", mock.Anything, []byte("not a script"), "fstest::/dir/not-a-script").
		Return(nil, model.ErrNoMatch).
		Once()

	noMatch.On("Detect", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, model.ErrNoMatch).
		Times(2)

	detectors := []scan.Detector{noMatch, isScript}
	scanner := scan.New(4, detectors)

	detections := make([]model.Detection, 0, 10)
	for detection, err := range scanner.Do(t.Context(), walk.FS(t.Context(), root, "fstest::")) {
		if errors.Is(err, model.ErrNoMatch) {
			continue
		}
		require.NoError(t, err)
		detections = append(detections, detection...)
	}

	require.Len(t, detections, 1)
	require.Equal(t, "fstest::/is-script", detections[0].Path)
	stats := scanner.Stats()
	require.NotNil(t, stats)
}

type MockDetector struct {
	mock.Mock
}

func NewMockDetector(t *testing.T) *MockDetector {
	d := new(MockDetector)
	t.Cleanup(func() { d.AssertExpectations(t) })
	return d
}

func (d *MockDetector) Detect(ctx context.Context, b []byte, path string) ([]model.Detection, error) {
	args := d.Called(ctx, b, path)
	var ret []model.Detection
	if x, ok := args.Get(0).([]model.Detection); ok {
		ret = x
	}
	return ret, args.Error(1)
}
