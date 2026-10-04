# Contributing to pulse

Thanks for your interest in improving `pulse`. This document covers the basics.

## Getting started

```sh
git clone https://github.com/StackZy-Lab/pulse
cd pulse
make test
```

Requires Go 1.23 or newer. The project has no third-party dependencies.

## Before you open a pull request

- Run `gofmt -w .`, `go vet ./...` and `go test -race ./...`.
- Add or update tests for behavior changes. Tests live beside the code they
  cover; use `net/http/httptest` for anything that touches the network.
- Keep commits focused and use a short, imperative subject, optionally prefixed
  with the package: `probe: classify expired certificates`, `cli: fix help text`.

## Project layout

| Path | Responsibility |
|---|---|
| `cmd/pulse` | Process entry point and signal handling. |
| `internal/cli` | Flags, prompt, run loop, exit codes. |
| `internal/probe` | The probing engine: HTTP, timings, TLS, redirects, classification. |
| `internal/report` | Text and JSON rendering. |
| `internal/term` | TTY/color detection, symbols, spinner. |

Presentation belongs in `report` and `term`; the engine in `probe` should stay
free of formatting and process concerns.

## Reporting bugs

Please include the `pulse --version` output, the command you ran (redact
secrets), and what you expected to see. For security issues, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.
