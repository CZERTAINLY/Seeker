package scan

import (
	"context"
	"fmt"
	"io"
	"iter"

	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/CZERTAINLY/Seeker/internal/walk"

	"golang.org/x/sync/errgroup"
)

type Detector interface {
	Detect(b []byte, path string) ([]model.Detection, error)
}

type Scan struct {
	limit        int
	skipIfBigger int64
	detectors    []Detector
}

func New(limit int, detectors []Detector) Scan {
	return Scan{
		limit:        limit,
		skipIfBigger: 10 * 1024 * 1024,
		detectors:    detectors,
	}
}

// Do reads the content of the seq iterator and runs scanning on the entries
// 1. If entry has a stat error, it's ignored
// 2. If is bigger than 10MB, it's ignored and ErrTooBig is returned
// 3. Otherwise the data are passed to the worker pool for running a detections
// 4. Returns an iterator with a detections or Open/Read error or a ErrNoMatch if not match is found
func (s Scan) Do(parentCtx context.Context, seq iter.Seq2[walk.Entry, error]) iter.Seq2[[]model.Detection, error] {
	return newParallelMap(parentCtx, s.limit, s.scan).iter(seq)
}

func (s Scan) scan(ctx context.Context, entry walk.Entry) ([]model.Detection, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	info, err := entry.Stat()
	if err != nil {
		return nil, fmt.Errorf("scan Stat: %w", err)
	}
	if info.Size() > s.skipIfBigger {
		return nil, fmt.Errorf("entry too big (%d bytes): %w", info.Size(), model.ErrTooBig)
	}

	f, err := entry.Open()
	if err != nil {
		return nil, fmt.Errorf("scan Open: %w", err)
	}
	defer func() {
		_ = f.Close() // ignoring close error for CLI tool
	}()

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("scan ReadAll: %w", err)
	}

	res := make([]model.Detection, 0, 10)
	for _, detector := range s.detectors {
		d, _ := detector.Detect(b, entry.Path())
		res = append(res, d...)
	}

	if len(res) == 0 {
		return nil, model.ErrNoMatch
	}
	return res, nil
}

type result[D any] struct {
	d D
	e error
}

type pMap[E, D any] struct {
	parentCtx    context.Context
	cancelParent context.CancelFunc
	g            *errgroup.Group
	gctx         context.Context
	mapped       chan result[D]
	mapFunc      func(context.Context, E) (D, error)
}

func newParallelMap[E, D any](parentCtx context.Context, limit int, mapFunc func(context.Context, E) (D, error)) *pMap[E, D] {
	parentCtx, cancelParent := context.WithCancel(parentCtx)
	g, gctx := errgroup.WithContext(parentCtx)
	g.SetLimit(limit + 1)

	detects := make(chan result[D], limit)

	return &pMap[E, D]{
		parentCtx:    parentCtx,
		cancelParent: cancelParent,
		g:            g,
		gctx:         gctx,
		mapped:       detects,
		mapFunc:      mapFunc,
	}
}

func (s *pMap[E, D]) goWorkers(seq iter.Seq2[E, error]) {
	s.g.Go(func() error {
		for entry, nerr := range seq {
			if nerr != nil {
				continue
			}
			s.g.Go(func() error {
				d, scanErr := s.mapFunc(s.gctx, entry)
				select {
				case <-s.gctx.Done():
					return s.gctx.Err()
				default:
					s.mapped <- result[D]{d: d, e: scanErr}
				}
				return nil
			})
		}
		return nil
	})
}

func (s *pMap[E, D]) iter(seq iter.Seq2[E, error]) iter.Seq2[D, error] {
	return func(yield func(D, error) bool) {
		defer s.cancelParent()
		s.goWorkers(seq)

		go func() {
			_ = s.g.Wait()
			close(s.mapped)
		}()

		for r := range s.mapped {
			if s.parentCtx.Err() != nil {
				return
			}
			if !yield(r.d, r.e) {
				return
			}
		}
	}
}
