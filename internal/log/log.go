package log

import (
	"context"
	"log/slog"
)

type slogKeyT struct{}

var slogKey slogKeyT

type ContextHandler struct {
	slog.Handler
}

func New(handler slog.Handler) ContextHandler {
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
