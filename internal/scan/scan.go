package scan

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/CZERTAINLY/Seeker/internal/log"
	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/CZERTAINLY/Seeker/internal/parallel"
	"github.com/CZERTAINLY/Seeker/internal/walk"
)

type Detector interface {
	Detect(ctx context.Context, b []byte, path string) ([]model.Detection, error)
}

type Scan struct {
	limit             int
	skipIfBigger      int64
	detectors         []Detector
	pool              sync.Pool
	poolNewCounter    atomic.Int32
	poolPutCounter    atomic.Int32
	poolPutErrCounter atomic.Int32
}

type Stats struct {
	PoolNewCounter    int
	PoolPutCounter    int
	PoolPutErrCounter int
}

func New(limit int, detectors []Detector) *Scan {
	const skipIfBigger = 10 * 1024 * 1024
	s := &Scan{
		limit:        limit,
		skipIfBigger: skipIfBigger,
		detectors:    detectors,
	}
	s.pool = sync.Pool{
		New: func() any {
			s.poolNewCounter.Add(1)
			b := make([]byte, skipIfBigger)
			return &b
		},
	}
	return s
}

// Do reads the content of the seq iterator and runs scanning on the entries
// 1. If entry has a stat error, it's ignored
// 2. If is bigger than 10MB, it's ignored and ErrTooBig is returned
// 3. Otherwise the data are passed to the worker pool for running a detections
// 4. Returns an iterator with a detections or Open/Read error or a ErrNoMatch if not match is found
func (s *Scan) Do(parentCtx context.Context, seq iter.Seq2[walk.Entry, error]) iter.Seq2[[]model.Detection, error] {
	return parallel.NewMap(parentCtx, s.limit, s.scan).Iter(seq)
}

func (s *Scan) scan(ctx context.Context, entry walk.Entry) ([]model.Detection, error) {
	ctx = log.ContextAttrs(ctx, slog.String("path", entry.Path()))
	slog.DebugContext(ctx, "scanning")
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	info, err := entry.Stat()
	if err != nil {
		return nil, fmt.Errorf("scan Stat: %w", err)
	}
	if info.Size() > s.skipIfBigger {
		slog.DebugContext(ctx, "scanning skiped, too big file", "size", info.Size())
		return nil, fmt.Errorf("entry too big (%d bytes): %w", info.Size(), model.ErrTooBig)
	}

	f, err := entry.Open()
	if err != nil {
		return nil, fmt.Errorf("scan Open: %w", err)
	}
	defer func() {
		_ = f.Close() // ignoring close error for CLI tool
	}()

	bp := s.pool.Get().(*[]byte)
	buf := *bp
	clear(buf)
	n, err := f.Read(buf)
	if err != nil {
		s.poolPutErrCounter.Add(1)
		s.pool.Put(bp)
		return nil, fmt.Errorf("scan ReadAll: %w", err)
	}
	// IMPORTANT: data must be passed as buf[:n] otherwise data from a previous
	// file will be passed in
	buf = buf[:n]

	var detectionErrors []error
	res := make([]model.Detection, 0, 10)
	for _, detector := range s.detectors {

		if ld, ok := detector.(interface{ LogAttrs() []slog.Attr }); ok {
			ctx = log.ContextAttrs(ctx, ld.LogAttrs()...)
		}

		d, err := detector.Detect(ctx, buf, entry.Path())
		s.poolPutCounter.Add(1)
		s.pool.Put(bp)
		switch {
		case err == nil:
			res = append(res, d...)
			// file was detected, so no point in trying other detectors
			continue
		case errors.Is(err, model.ErrNoMatch):
			// ignore ErrNoMatch
		default:
			detectionErrors = append(detectionErrors, err)
		}
	}

	if len(res) == 0 {
		return nil, model.ErrNoMatch
	} else if len(detectionErrors) > 0 {
		return nil, errors.Join(detectionErrors...)
	}

	return res, nil
}

func (s *Scan) Stats() Stats {
	return Stats{
		PoolNewCounter:    int(s.poolNewCounter.Load()),
		PoolPutCounter:    int(s.poolPutCounter.Load()),
		PoolPutErrCounter: int(s.poolPutErrCounter.Load()),
	}
}
