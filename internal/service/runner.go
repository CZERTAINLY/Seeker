package service

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"
)

var (
	ErrScanNotStarted = errors.New("scan not started")
	ErrScanInProgress = errors.New("scan in progress")
)

type StderrFunc func(ctx context.Context, line string)

type Runner struct {
	mx         sync.RWMutex
	cmd        *exec.Cmd
	cancelFunc context.CancelFunc
	result     Result
	waits      []chan Result
}

func NewRunner() *Runner {
	return &Runner{
		result: Result{Err: ErrScanNotStarted},
	}
}

type Command struct {
	Path    string
	Args    []string
	Env     []string
	Timeout time.Duration
}

type Result struct {
	Path    string
	Args    []string
	Env     []string
	Started time.Time
	Stopped time.Time
	State   *os.ProcessState
	Stdout  *bytes.Buffer
	Err     error
}

// Start run the underlying process, it ensure only single instance of a binary is active
// returns ErrScanInProgress or an exec error, otherwise nil. Does NOT wait on
// command to finish, use WaitChan method instead.
// Note it spawn an internal gorutine which monitor the started command and stderr
func (r *Runner) Start(ctx context.Context, proto Command, stderrFunc StderrFunc) error {
	r.mx.Lock()
	defer r.mx.Unlock()
	if r.cmd != nil {
		return ErrScanInProgress
	}

	r.result = Result{
		Path: proto.Path,
		Args: append([]string(nil), proto.Args...),
		Env:  append([]string(nil), proto.Env...),
		Err:  nil,
	}

	if proto.Timeout == 0 {
		slog.WarnContext(ctx, "command has no timeout", "path", proto.Path)
	} else {
		ctx, r.cancelFunc = context.WithTimeout(ctx, proto.Timeout)
	}

	r.cmd = exec.CommandContext(ctx, r.result.Path, r.result.Args...)
	r.cmd.Env = r.result.Env
	slog.Debug("r.cmd.Env", "e", r.cmd.Env)
	var stderr io.ReadCloser
	if stderrFunc != nil {
		var err error
		stderr, err = r.cmd.StderrPipe()
		if err != nil {
			return err
		}
	}
	var buf bytes.Buffer
	r.result.Stdout = &buf
	r.cmd.Stdout = &buf

	r.result.Started = time.Now().UTC()
	if err := r.cmd.Start(); err != nil {
		r.result.Stopped = time.Now().UTC()
		r.result.Err = err
		r.cmd = nil
		return err
	}

	if stderr != nil {
		go r.processStderr(ctx, stderr, stderrFunc)
	}
	go r.wait(r.cmd)
	return nil
}

func (r *Runner) processStderr(ctx context.Context, stderr io.Reader, stderrFunc StderrFunc) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		stderrFunc(ctx, scanner.Text())
	}
	err := scanner.Err()
	if err != nil && !errors.Is(err, io.EOF) {
		slog.ErrorContext(ctx, "processing stderr", "error", err)
	}
}

func (r *Runner) wait(cmd *exec.Cmd) {
	err := cmd.Wait()
	if r.cancelFunc != nil {
		r.cancelFunc()
	}
	stopped := time.Now().UTC()

	r.mx.Lock()
	defer r.mx.Unlock()
	r.result.Stopped = stopped
	r.result.State = cmd.ProcessState
	r.result.Err = err
	r.cmd = nil
	for _, ch := range r.waits {
		ch <- r.result
		close(ch)
	}
}

/*
FIXME:
panic: send on closed channel

goroutine 29 [running]:
github.com/CZERTAINLY/Seeker/internal/service.(*Runner).wait(0xc000428000, 0xc000522000)
        /home/michal/projects/3key/Seeker/internal/service/runner.go:134 +0x1e5
created by github.com/CZERTAINLY/Seeker/internal/service.(*Runner).Start in goroutine 23
        /home/michal/projects/3key/Seeker/internal/service/runner.go:105 +0x878
*/

// WaitChan returns the channel obtaining the result of a running
// program. The channel is closed once program ends.
func (r *Runner) WaitChan() <-chan Result {
	ch := make(chan Result, 1)
	r.mx.Lock()
	r.waits = append(r.waits, ch)
	r.mx.Unlock()
	return ch
}

// Result returns a last command result
// or result with ErrScanNotStarted/ErrScanInProgress
// if no scan have been executed yet
func (r *Runner) Result() Result {
	r.mx.RLock()
	defer r.mx.RUnlock()
	return r.result
}
