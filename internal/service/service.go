package service

import (
	"bytes"
	"context"
	"log/slog"
	"os"
)

type Uploader interface {
	Upload(ctx context.Context, raw []byte) error
}

type Supervisor struct {
	cmd      Command
	start    chan struct{}
	uploader Uploader
}

func NewSupervisor(cmd Command, uploader Uploader) *Supervisor {
	return &Supervisor{
		cmd:      cmd,
		start:    make(chan struct{}),
		uploader: uploader,
	}
}

func (s *Supervisor) Do(ctx context.Context) {
	slog.DebugContext(ctx, "starting a supervisor")
	runner := NewRunner()
	defer runner.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.start:
			slog.DebugContext(ctx, "about to start", "command", s.cmd)
			err := s.callStart(ctx, runner)
			if err != nil {
				slog.ErrorContext(ctx, "start returned", "error", err)
			}
		case result := <-runner.ResultsChan():
			if result.State == nil || result.State.ExitCode() != 0 {
				slog.ErrorContext(ctx, "scan have failed", "result", result)
				continue
			}
			slog.DebugContext(ctx, "scan succeeded: uploading")
			err := s.upload(ctx, result.Stdout)
			if err != nil {
				slog.ErrorContext(ctx, "upload failed", "error", err)
				continue
			}
		}
	}
}

func (s *Supervisor) Start() {
	s.start <- struct{}{}
}

func (s *Supervisor) callStart(ctx context.Context, runner *Runner) error {
	return runner.Start(ctx, s.cmd, nil)
}

func (s *Supervisor) upload(ctx context.Context, stdout *bytes.Buffer) error {
	return s.uploader.Upload(ctx, stdout.Bytes())
}

type StdoutUploader struct{}

func (s StdoutUploader) Upload(_ context.Context, raw []byte) error {
	_, err := os.Stdout.Write(raw)
	return err
}
