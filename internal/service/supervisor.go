package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/model"
)

type Supervisor struct {
	cmd       Command
	start     chan struct{}
	uploaders []Uploader
	oneshot   bool
}

func NewSupervisor(cmd Command, uploaders ...Uploader) *Supervisor {
	return &Supervisor{
		cmd:       cmd,
		start:     make(chan struct{}),
		uploaders: uploaders,
	}
}

func SupervisorFromConfig(ctx context.Context, cfg model.Service, configPath string) (*Supervisor, error) {
	uploaders, err := uploaders(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("inicializing uploaders: %w", err)
	}
	seeker, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("cannot determine path to executable: %w", err)
	}
	cmd := Command{
		Path: seeker,
		Args: []string{"_scan", "--config", configPath},
		Env: []string{
			"HOME=" + os.Getenv("HOME"),
			"GODEBUG=tlssha1=1,x509rsacrt=0,x509negativeserial=1",
		},
		// TODO: scan timeout
		Timeout: 0,
	}

	return &Supervisor{
		cmd:       cmd,
		start:     make(chan struct{}),
		uploaders: uploaders,
		oneshot:   cfg.Mode == "manual",
	}, nil
}

func (s *Supervisor) Do(ctx context.Context) {
	slog.DebugContext(ctx, "starting a supervisor")
	runner := NewRunner(nil)
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
			if result.State == nil || result.State.ExitCode() != 0 || result.Err != nil {
				slog.ErrorContext(ctx, "scan have failed", "result", result)
				continue
			}
			slog.DebugContext(ctx, "scan succeeded: uploading")
			err := s.upload(ctx, result.Stdout)
			if err != nil {
				slog.ErrorContext(ctx, "upload failed", "error", err)
				continue
			}
			if s.oneshot {
				return
			}
		}
	}
}

func (s *Supervisor) Start() {
	s.start <- struct{}{}
}

func (s *Supervisor) callStart(ctx context.Context, runner *Runner) error {
	return runner.Start(ctx, s.cmd)
}

func (s *Supervisor) upload(ctx context.Context, stdout *bytes.Buffer) error {
	var errs []error
	for _, u := range s.uploaders {
		err := u.Upload(ctx, stdout.Bytes())
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func uploaders(ctx context.Context, cfg model.Service) ([]Uploader, error) {
	if cfg.Dir == nil && (cfg.Repository == nil || !get(cfg.Repository.Enabled)) {
		return []Uploader{NewWriteUploader(os.Stdout)}, nil
	}
	var uploaders []Uploader
	if cfg.Dir != nil {
		u, err := newOsRootUploader(*cfg.Dir)
		if err != nil {
			return nil, err
		}
		uploaders = append(uploaders, u)
	}
	if cfg.Repository != nil {
		slog.WarnContext(ctx, "repository support is not yet implemented")
	}
	return uploaders, nil
}

type WriteUploader struct {
	w io.Writer
}

func NewWriteUploader(w io.Writer) WriteUploader {
	return WriteUploader{w: w}
}

func (u WriteUploader) Upload(_ context.Context, raw []byte) error {
	if u.w == nil {
		u.w = os.Stdout
	}
	_, err := u.w.Write(raw)
	return err
}

type osRootUploader struct {
	root *os.Root
}

func newOsRootUploader(path string) (*osRootUploader, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &osRootUploader{root: root}, nil
}

func (u *osRootUploader) Upload(_ context.Context, b []byte) error {
	if u.root == nil {
		return errors.New("root already closed")
	}

	f, err := u.root.Create("seeker-" + time.Now().Format("2006-01-02-03:04:05") + ".json")
	if err != nil {
		return fmt.Errorf("storing seeker results: %w", err)
	}
	_ = f.Close()
	_ = u.root.Close()
	u.root = nil
	return nil
}
