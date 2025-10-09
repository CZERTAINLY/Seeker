package service

import (
	"context"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"

	"github.com/CZERTAINLY/Seeker/internal/bom"
	"github.com/CZERTAINLY/Seeker/internal/gitleaks"
	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/CZERTAINLY/Seeker/internal/scan"
	"github.com/CZERTAINLY/Seeker/internal/walk"
	"github.com/CZERTAINLY/Seeker/internal/x509"
	"golang.org/x/sync/errgroup"
)

var detectors []scan.Detector

func init() {
	leaks, err := gitleaks.NewDetector()
	if err != nil {
		panic(err)
	}

	detectors = []scan.Detector{
		x509.Detector{},
		leaks,
	}
}

type Uploader interface {
	Upload(ctx context.Context, raw []byte) error
}

// Scanner is a component, which encapsulates the scan functionality and executes it.
type Scanner struct {
	filesystems iter.Seq2[walk.Entry, error]
}

func NewScanner(ctx context.Context, config model.Config) (Scanner, error) {
	if config.Version != 0 {
		return Scanner{}, fmt.Errorf("config version %d is not supported, expected 0", config.Version)
	}

	filesystems, err := filesystems(ctx, config.Filesystem)
	if err != nil {
		return Scanner{}, fmt.Errorf("initializing filesystem scan: %w", err)
	}

	return Scanner{
		filesystems: filesystems,
	}, nil
}

func (s Scanner) Do(ctx context.Context, out io.Writer) error {
	g, ctx := errgroup.WithContext(ctx)

	b := bom.NewBuilder()
	detections := make(chan model.Detection)
	go func() {
		for d := range detections { // will be done after g.Wait()
			b.AppendComponents(d.Components...)
			b.AppendDependencies(d.Dependencies...)
		}
	}()

	// filesystem scanners
	scanner := scan.New(4, detectors)
	g.Go(func() error {
		for results, err := range scanner.Do(ctx, s.filesystems) {
			if err != nil {
				slog.DebugContext(ctx, "error on filesystem scan", "error", err)
				continue
			}
			for _, detection := range results {
				detections <- detection
			}
		}
		return nil
	})

	_ = g.Wait() // goroutines do not return an error
	close(detections)

	err := b.AsJSON(out)
	if err != nil {
		return fmt.Errorf("formatting BOM as JSON: %w", err)
	}
	return nil
}

func filesystems(ctx context.Context, cfg *model.Filesystem) (iter.Seq2[walk.Entry, error], error) {
	var filesystems iter.Seq2[walk.Entry, error]
	if cfg == nil || !get(cfg.Enabled) {
		return filesystems, nil
	}

	paths := cfg.Paths
	if paths == nil {
		cwd, err := os.Getwd()
		if err != nil {
			return filesystems, fmt.Errorf("getting working directory: %w", err)
		}
		paths = []string{cwd}
	}

	roots := make([]*os.Root, 0, len(paths))
	for _, path := range paths {
		root, err := os.OpenRoot(path)
		if err != nil {
			return filesystems, fmt.Errorf("opening filesystem dir: %w", err)
		}
		roots = append(roots, root)
	}
	return walk.Roots(ctx, roots...), nil
}

func get[T any](pt *T) T {
	var zero T
	if pt == nil {
		return zero
	}
	return *pt
}
