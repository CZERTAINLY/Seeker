package service

// Package service implements supervision and execution of scan subprocesses.
//
// Overview
// The Supervisor owns an event loop and a registry of uniquely named Jobs.
// Clients register a Job, then request it to start. Only one instance per
// name may run at a time.
//
// A Job wraps a model.Scan plus the command to execute. It validates the scan,
// starts work, and forwards results and errors through its channels. The current
// implementation supports one-shot jobs: they terminate after the first success
// or error. Calling Start while a job is already running returns an error.
//
// Runner is a thin, opinionated wrapper around os/exec:
//   - starts the process
//   - writes configuration to stdin
//   - captures stdout
//   - optionally captures stderr (extra goroutine)
//   - exposes a channel of Result values
//
// Data flow:
//
//   Supervisor            Job{name}               Runner{cmd}
//       |                    |                       |
//   add -> register -------->|                       |
//       | start() ---------->| Run()/Start() ------->| Start()
//       |                    |                       | os/exec.Start + Wait() in goroutine
//       |                    |                       | stderr capture goroutine
//       |                    |<------ Result --------| (process exits)
//       |<------ Result -----|                       |
//
// The Supervisor is responsible for uploading results and scheduling time-based
// executions.
//
// Invariants:
//   - At most one Runner per Job at a time.
//   - Parallel scanning is done via multiple Jobs
//   - Each execution produces one terminal Result (success or error).
//   - Stderr is captured only when explicitly requested.
//   - Stdout is captured after program is done.
//   - Each run can define own timeout, after which is gets killed
//
// internal/service/service_test.go is the best source about how to properly user
// Supervisor struct.
