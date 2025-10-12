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
	uploaders []model.Uploader
	oneshot   bool
}

func NewSupervisor(cmd Command, uploaders ...model.Uploader) *Supervisor {
	return &Supervisor{
		cmd:       cmd,
		start:     make(chan struct{}, 1),
		uploaders: uploaders,
	}
}

func (s *Supervisor) SetOneshot(oneshot bool) *Supervisor {
	s.oneshot = oneshot
	return s
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
	args := []string{
		"_scan",
		"--config",
		configPath,
	}
	if cfg.Verbose {
		args = append(args, "--verbose")
	}
	cmd := Command{
		Path: seeker,
		Args: args,
		Env: append(
			os.Environ(),
			"GODEBUG=tlssha1=1,x509rsacrt=0,x509negativeserial=1",
		),
		// TODO: scan timeout
		Timeout: 0,
	}

	return &Supervisor{
		cmd:       cmd,
		start:     make(chan struct{}, 1),
		uploaders: uploaders,
		oneshot:   cfg.Mode == model.ServiceModeManual,
	}, nil
}

// Do performs in two different modes
// "manual" aka oneshot - in this case scan and upload is executed once and its error is returned
// others: errors are only logged and never returned
func (s *Supervisor) Do(ctx context.Context) error {
	slog.DebugContext(ctx, "starting a supervisor")
	runner := NewRunner(nil)
	defer runner.Close()

	if s.oneshot {
		slog.DebugContext(ctx, "starting oneshot job")
		s.Start()
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.start:
			slog.DebugContext(ctx, "about to start", "command", s.cmd)
			err := s.callStart(ctx, runner)
			if err != nil {
				if s.oneshot {
					return err
				}
				slog.ErrorContext(ctx, "start returned", "error", err)
			}
		case result := <-runner.ResultsChan():
			if result.State == nil || result.State.ExitCode() != 0 || result.Err != nil {
				slog.ErrorContext(ctx, "scan have failed", "result", result)
				continue
			}
			slog.DebugContext(ctx, "scan succeeded: uploading")
			err := s.upload(ctx, result.Stdout)
			if s.oneshot {
				return err
			}
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

func uploaders(ctx context.Context, cfg model.Service) ([]model.Uploader, error) {
	if cfg.Dir == "" && !cfg.Repository.Enabled {
		return []model.Uploader{NewWriteUploader(os.Stdout)}, nil
	}
	var uploaders []model.Uploader
	if cfg.Dir != "" {
		u, err := NewOSRootUploader(cfg.Dir)
		if err != nil {
			return nil, err
		}
		uploaders = append(uploaders, u)
	}
	if cfg.Repository.Enabled {
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

type OSRootUploader struct {
	root *os.Root
}

func NewOSRootUploader(path string) (*OSRootUploader, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &OSRootUploader{root: root}, nil
}

func (u *OSRootUploader) Upload(ctx context.Context, b []byte) error {
	if u.root == nil {
		return errors.New("root already closed")
	}

	path := "seeker-" + time.Now().Format("2006-01-02-15-04-05") + ".json"

	f, err := u.root.Create(path)
	if err != nil {
		return fmt.Errorf("creating seeker results: %w", err)
	}
	_, err = f.Write(b)
	if err != nil {
		return fmt.Errorf("saving seeker results: %w", err)
	}
	err = f.Close()
	if err != nil {
		return fmt.Errorf("closing seeker result: %w", err)
	}
	err = u.root.Close()
	if err != nil {
		return fmt.Errorf("closing seeker result's dir: %w", err)
	}
	slog.InfoContext(ctx, "bom saved", "path", path)
	u.root = nil
	return nil
}
