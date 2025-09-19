package parallel_test

import (
	"context"
	"iter"
	"testing"
	"testing/synctest"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/parallel"
	"github.com/stretchr/testify/require"
)

func TestMap(t *testing.T) {
	t.Parallel()

	f := func(_ context.Context, d time.Duration) (int, error) {
		time.Sleep(d)
		return int(d), nil
	}

	input := []time.Duration{1 * time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second}
	expected := []int{
		int(1 * time.Second),
		int(2 * time.Second),
		int(5 * time.Second),
		int(10 * time.Second),
	}

	type given struct {
		limit int
		ctx   func(t *testing.T) context.Context
	}
	tCtx := func(t *testing.T) context.Context {
		t.Helper()
		return t.Context()
	}
	tmout1s := func(t *testing.T) context.Context {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 1*time.Second)
		t.Cleanup(cancel)
		return ctx
	}

	var testCases = []struct {
		scenario string
		given    given
		then     time.Duration
	}{
		{"limit 1", given{1, tCtx}, 18 * time.Second},
		{"limit 10", given{10, tCtx}, 10 * time.Second},
		{"limit 1, cancel 1s", given{1, tmout1s}, 1 * time.Second},
		{"limit 10, cancel 1s", given{10, tmout1s}, 1 * time.Second},
	}

	for _, tt := range testCases {
		t.Run(tt.scenario, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				m1 := parallel.NewMap(tt.given.ctx(t), tt.given.limit, f).Iter(all(input))
				require.ElementsMatch(t, expected, values(m1))
				t.Logf("since: %+v", time.Since(start))
				require.Equal(t, tt.then, time.Since(start))
			})
		})
	}

}

func all[T any](s []T) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		for _, x := range s {
			if !yield(x, nil) {
				return
			}
		}
	}
}

func values[T any](i iter.Seq2[T, error]) []T {
	var ret []T
	for k := range i {
		ret = append(ret, k)
	}
	return ret
}
