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

	gocron "github.com/go-co-op/gocron/v2"

	"github.com/CZERTAINLY/Seeker/internal/model"
)

type Supervisor struct {
	cmd       Command
	start     chan struct{}
	uploaders []model.Uploader
	oneshot   bool
	scheduler gocron.Scheduler
}

func NewSupervisor(ctx context.Context, cfg model.Service, configPath string) (*Supervisor, error) {
	uploaders, err := uploaders(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("initializing uploaders: %w", err)
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

	var supervisor = &Supervisor{}
	var scheduler gocron.Scheduler
	if cfg.Mode == "timer" {
		var err error
		scheduler, err = newScheduler(ctx, cfg, supervisor.Start)
		if err != nil {
			return nil, fmt.Errorf("timer mode failed: %w", err)
		}
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

	supervisor.cmd = cmd
	supervisor.start = make(chan struct{}, 1)
	supervisor.uploaders = uploaders
	supervisor.oneshot = (cfg.Mode == model.ServiceModeManual)
	supervisor.scheduler = scheduler

	return supervisor, nil
}

// WithCmdUploaders changes a command and uploaders for a initialized Supervisor.
// This method exists for a unit testing only.
func (s *Supervisor) WithCmdUploaders(ctx context.Context, cmd Command, uploaders ...model.Uploader) *Supervisor {
	s.closeUploaders(ctx)
	s.uploaders = uploaders
	s.cmd = cmd
	return s
}

func (s *Supervisor) closeUploaders(ctx context.Context) {
	for _, uploader := range s.uploaders {
		if closer, ok := uploader.(model.UploadCloser); ok {
			err := closer.Close()
			if err != nil {
				slog.ErrorContext(ctx, "closing uploader have failed", "error", err)
			}
		}
	}
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

	if s.scheduler != nil {
		s.scheduler.Start()
		defer func() {
			err := s.scheduler.Shutdown()
			if err != nil {
				slog.ErrorContext(ctx, "shutting down the gocron have failed", "error", err)
			}
		}()
	}

	defer func() {
		s.closeUploaders(ctx)
	}()

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

func newScheduler(ctx context.Context, cfg model.Service, startFunc func()) (gocron.Scheduler, error) {
	fields, err := ParseFlexible(cfg.Every)
	if err != nil {
		return nil, fmt.Errorf("service.every has a wrong format: %w", err)
	}
	slog.DebugContext(ctx, "detected crontab", "fields", fields)

	s, err := gocron.NewScheduler()
	if err != nil {
		return nil, fmt.Errorf("initializing gocron scheduler: %w", err)
	}
	_, err = s.NewJob(
		gocron.CronJob(cfg.Every, fields == 6),
		gocron.NewTask(startFunc),
	)
	if err != nil {
		return nil, fmt.Errorf("initializing gocron job: %w", err)
	}
	return s, nil
}

func uploaders(_ context.Context, cfg model.Service) ([]model.Uploader, error) {
	if cfg.Dir == "" && (cfg.Repository == nil || !cfg.Repository.Enabled) {
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

	if cfg.Repository != nil && cfg.Repository.Enabled {
		u, err := NewBOMRepoUploader(cfg.Repository.URL)
		if err != nil {
			return nil, err
		}
		uploaders = append(uploaders, u)
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
	slog.InfoContext(ctx, "bom saved", "path", path)
	return nil
}

func (u *OSRootUploader) Close() error {
	if u.root == nil {
		return errors.New("root already closed")
	}
	err := u.root.Close()
	u.root = nil
	return err
}
