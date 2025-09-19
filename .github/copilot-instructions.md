# Copilot Instructions for This Project

This repository is a **Go CLI utility**. It is intended to traverse FS, or OCI images, or ports and detect any cryprographic material.
When suggesting code, documentation, or reviews, please follow these guidelines:

## General
- Always prefer **idiomatic Go**: clear names, short functions, explicit error handling.
- When possible, keep the standard library as the default; add dependencies only when necessary.

## CLI Design
- The project uses spf13/cobra and spf13/viper for command line and environment values and config gile parsing.
- Suggest helpful, human-friendly error messages and usage output.
- Prefer descriptive flag names with sensible defaults.
- Document new commands or flags in `README.md`.

## Logging and Errors
- Use structured logging log/slog if present, otherwise standard `log` or `fmt.Fprintf(os.Stderr, ...)`.
- Use of a default slog.Logger is fine as this is a CLI utility.
- Return errors instead of `panic` unless startup conditions fail irrecoverably.
- Include context in error messages (what the program was doing).
- Suggest helpful, human-friendly errors and logs.

## Concurrency patterns and contex
- Code contains a parallel processing facilitated by errgroups.Group
- Avoid raw goroutines - the only exception is the goroutine waiting on the errgroups.Group itself
- Make sure channel operations are correct and channel is closed when not needed
- Make sure reads from a channels are in for value, ok := <- ch
- The rule can be ignored in a case of waiting pattern, like ctx.Done(), time.After() when channel is used for a signalling
- Ensure all sync.Pool correctly return the data
- context.TODO() is not allowed
- context.Background() can be only in main.go

## Security and Robustness
- Validate all user input.
- Avoid insecure functions or patterns.
- However ignore warnings about deprecated crypto packages like crypto/dsa - the purpose of this tool is to parse as much formats as possible.
- When handling files or network input, check permissions and bounds.

## Testing
- For new features, suggest corresponding unit tests.
- Tests should be table-driven where practical.
- Keep tests deterministic (no reliance on current time, random ports, etc., unless explicitly seeded).
- Prefer github.com/stretchr/testify modules for testing - require and mock
- Use the go 1.25+ idiomatic testing with t.Context(), t.Output(), testing/synctest and so

## Documentation
- Add Go doc comments (`// FunctionName ...`) for all exported identifiers.
- Update `README.md` when changing CLI behavior.
- Suggest examples in `docs/` or usage snippets in README.

## Performance
- Avoid premature optimization, but keep an eye on obvious inefficiencies.
- Prefer streaming or buffered IO for large files.

## Project Style
- Respect existing project patterns and module structure.
- Prefer small, composable packages over monoliths.
