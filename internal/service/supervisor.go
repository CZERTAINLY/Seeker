package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	gocron "github.com/go-co-op/gocron/v2"

	"github.com/CZERTAINLY/Seeker/internal/model"
)

type Supervisor struct {
	start     chan string
	uploaders []model.Uploader
	oneshot   bool
	scheduler gocron.Scheduler
	results   chan Result
	jobsChan  chan job
	jobsMx    sync.Mutex
	jobs      map[string]*Job
	wg        sync.WaitGroup
}

type jobOp int

const (
	jobOpAdd jobOp = iota
	jobOpConfigure
)

type job struct {
	op     jobOp
	name   string
	job    *Job
	config *model.Scan
}

func NewSupervisor(ctx context.Context, cfg model.Config) (*Supervisor, error) {
	svcCfg := cfg.Service
	uploaders, err := uploaders(ctx, svcCfg)
	if err != nil {
		return nil, fmt.Errorf("initializing uploaders: %w", err)
	}

	var supervisor = &Supervisor{}
	var scheduler gocron.Scheduler
	if svcCfg.Mode == "timer" {
		var err error
		scheduler, err = newScheduler(ctx, svcCfg.Schedule, func() { supervisor.Start("**") })
		if err != nil {
			return nil, fmt.Errorf("timer mode failed: %w", err)
		}
	}

	supervisor.uploaders = uploaders
	supervisor.oneshot = (svcCfg.Mode == model.ServiceModeManual)
	supervisor.scheduler = scheduler

	supervisor.start = make(chan string, 1)
	supervisor.results = make(chan Result, 1)
	supervisor.jobsChan = make(chan job, 1)
	supervisor.jobs = make(map[string]*Job)

	return supervisor, nil
}

// WithUploaders changes a command and uploaders for a initialized Supervisor.
// This method exists for a unit testing only.
func (s *Supervisor) WithUploaders(ctx context.Context, uploaders ...model.Uploader) *Supervisor {
	s.closeUploaders(ctx)
	s.uploaders = uploaders
	return s
}

// AddJob registers a new job which will be started in Do routine
// optional testData sets test override standard outputs for an existing job. Non-empty values make the job emit them and skip the real scan
// (hidden integration test protocol). For spawning / stream capture tests only;
// not for production use.
func (s *Supervisor) AddJob(ctx context.Context, name string, cfg model.Scan, testData ...string) {
	j, err := NewJob(name, s.oneshot, cfg, s.results)
	// internal test harness protocol
	if len(testData) == 1 {
		j.WithTestData(testData[0], "")
	} else if len(testData) == 2 {
		j.WithTestData(testData[0], testData[1])
	}

	if err != nil {
		slog.ErrorContext(ctx, "job can't be created: ignoring", "job_name", name, "error", err)
		return
	}
	s.jobsChan <- job{op: jobOpAdd, name: name, job: j}
}

// ConfigureJob allows added job to change its configuration
func (s *Supervisor) ConfigureJob(_ context.Context, name string, cfg model.Scan) {
	s.jobsChan <- job{op: jobOpConfigure, name: name, config: &cfg}
}

// Start tells supervisor to start a new scan - this hints as a signal, so this
// ends immediately and without any error.
// start "**" will trigger all registered jobs
func (s *Supervisor) Start(name string) {
	s.start <- name
}

// Do runs the supervisor event loop.
// It multiplexes four concerns:
//  1. Start triggers (job names/patterns received on s.start) – callStart launches those jobs.
//  2. Dynamic job additions (received on s.jobsChan) – handleJob registers and prepares them to be started.
//  3. Job results (from s.results) – validates process exit state; on success uploads stdout; on failure logs.
//  4. Context cancellation – terminates the loop and begins shutdown.
//
// Modes:
//   - Oneshot (manual): a wildcard start "**" is triggered once on entry; the first scan or upload error is returned.
//   - Other modes: errors are only logged; the loop runs until ctx is cancelled.
//
// Startup: starts the scheduler (if present).
// Shutdown (deferred order): closeJobs -> closeUploaders -> wait on s.wg (job goroutines).
// Returns nil on graceful cancellation, or the first error in oneshot mode.
func (s *Supervisor) Do(ctx context.Context) error {
	slog.DebugContext(ctx, "starting a supervisor")

	if s.scheduler != nil {
		s.scheduler.Start()
		defer func() {
			err := s.scheduler.Shutdown()
			if err != nil {
				slog.ErrorContext(ctx, "shutting down gocron has failed", "error", err)
			}
		}()
	}

	defer func() {
		s.closeJobs()
	}()

	defer func() {
		s.closeUploaders(ctx)
	}()

	defer func() {
		s.wg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case j, ok := <-s.jobsChan:
			if ok {
				s.handleJob(ctx, j)
			}
		case name := <-s.start:
			err := s.callStart(ctx, name)
			if err != nil {
				if s.oneshot {
					return err
				}
				slog.ErrorContext(ctx, "start returned", "error", err)
			}
		case result := <-s.results:
			var reason string
			switch {
			case result.Err != nil:
				reason = "err: " + result.Err.Error()
			case result.State == nil:
				reason = "state is nil"
			case result.State.ExitCode() != 0:
				reason = "exit code " + strconv.Itoa(result.State.ExitCode())
			}
			if reason != "" {
				slog.ErrorContext(ctx, "scan have failed", "reason", reason, "result", result)
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

func (s *Supervisor) closeJobs() {
	s.jobsMx.Lock()
	defer s.jobsMx.Unlock()

	for name, job := range s.jobs {
		job.Close()
		delete(s.jobs, name)
	}
}

func (s *Supervisor) handleJob(ctx context.Context, j job) {
	switch j.op {
	case jobOpAdd:
		if j.job == nil {
			slog.WarnContext(ctx, "job add nil: ignoring add", "job_name", j.name)
			return
		}
		s.handleJobAdd(ctx, j)
	case jobOpConfigure:
		if j.config == nil {
			slog.WarnContext(ctx, "job config nil: ignoring configure", "job_name", j.name)
			return
		}
		s.handleJobConfigure(ctx, j.name, *j.config)
	default:
		slog.WarnContext(ctx, "job operation not supported: ignoring", "op", j.op)
	}
}

func (s *Supervisor) handleJobAdd(ctx context.Context, j job) {
	s.jobsMx.Lock()
	defer s.jobsMx.Unlock()
	job := j.job
	if _, ok := s.jobs[job.Name()]; ok {
		slog.WarnContext(ctx, "job already added: ignoring", "job_name", job.Name())
		return
	}

	s.wg.Go(func() {
		slog.InfoContext(ctx, "adding new active job", "job_name", job.Name())
		err := job.Run(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "job run failed", "job_name", job.Name(), "error", err)
		}
	})
	s.jobs[job.Name()] = job
}

func (s *Supervisor) handleJobConfigure(ctx context.Context, name string, config model.Scan) {
	s.jobsMx.Lock()
	defer s.jobsMx.Unlock()
	if jobp, ok := s.jobs[name]; !ok {
		slog.WarnContext(ctx, "job not added: ignoring configure", "job_name", name)
		return
	} else {
		jobp.MergeConfig(config)
	}
}

func (s *Supervisor) callStart(ctx context.Context, name string) error {
	s.jobsMx.Lock()
	defer s.jobsMx.Unlock()

	if name == "**" {
		slog.DebugContext(ctx, "triggering all jobs")
		for jobName, job := range s.jobs {
			slog.DebugContext(ctx, "starting a job", "job_name", jobName)
			job.Start()
		}
		return nil
	}

	if job, ok := s.jobs[name]; !ok {
		slog.WarnContext(ctx, "cannot start job: not known", "job_name", name)
	} else {
		slog.DebugContext(ctx, "starting a job", "job_name", name)
		job.Start()
	}

	return nil
}

func (s *Supervisor) upload(ctx context.Context, stdout []byte) error {
	var errs []error
	for _, u := range s.uploaders {
		err := u.Upload(ctx, stdout)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func newScheduler(ctx context.Context, cfgp *model.TimerSchedule, startFunc func()) (gocron.Scheduler, error) {
	if cfgp == nil {
		return nil, fmt.Errorf("service.schedule is nil")
	}
	cfg := *cfgp
	var job gocron.JobDefinition
	switch {
	case cfg.Cron != "":
		err := ParseCron(cfg.Cron)
		if err != nil {
			return nil, fmt.Errorf("parsing service.scheduler.cron: %w", err)
		}
		job = gocron.CronJob(cfg.Cron, false)
		slog.DebugContext(ctx, "successfully parsed", "cron", cfg.Cron, "job", job)
	case cfg.Duration != "":
		d, err := ParseISODuration(cfg.Duration)
		if err != nil {
			return nil, fmt.Errorf("parsing service.scheduler.duration: %w", err)
		}
		slog.DebugContext(ctx, "successfully parsed", "duration", d.String(), "job", job)
		job = gocron.DurationJob(d)
	default:
		return nil, errors.New("both cron and duration are empty")
	}

	s, err := gocron.NewScheduler()
	if err != nil {
		return nil, fmt.Errorf("initializing gocron scheduler: %w", err)
	}
	_, err = s.NewJob(
		job,
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
		return errors.New("uploader already closed")
	}
	err := u.root.Close()
	u.root = nil
	return err
}
