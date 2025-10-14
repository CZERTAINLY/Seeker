package log

import (
	"context"
	"log/slog"
	"os"
)

type slogKeyT struct{}

var slogKey slogKeyT

type ContextHandler struct {
	slog.Handler
}

func NewContextHandler(handler slog.Handler) ContextHandler {
	return ContextHandler{
		Handler: handler,
	}
}

func (h ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if a, ok := ctx.Value(slogKey).([]slog.Attr); ok {
		r.AddAttrs(a...)
	}

	return h.Handler.Handle(ctx, r)
}

func ContextAttrs(ctx context.Context, attrs ...slog.Attr) context.Context {
	a, ok := ctx.Value(slogKey).([]slog.Attr)
	if !ok || a == nil {
		a = make([]slog.Attr, 0, len(attrs))
	}
	a = append(a, attrs...)
	return context.WithValue(ctx, slogKey, a)
}

func New(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	base := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: false,
		Level:     level,
	})
	ctxHandler := NewContextHandler(base)
	return slog.New(ctxHandler)
}
