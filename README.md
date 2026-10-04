# pulse

[![CI](https://github.com/StackZy-Lab/pulse/actions/workflows/ci.yml/badge.svg)](https://github.com/StackZy-Lab/pulse/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/StackZy-Lab/pulse.svg)](https://pkg.go.dev/github.com/StackZy-Lab/pulse)

**Check the health of any URL from your terminal.**

`pulse` probes an HTTP(S) endpoint one or more times and prints a detailed
report for each check: HTTP status, per-phase latency, TLS details, redirects
and security findings. It is a single static binary with no runtime
dependencies.

```console
$ pulse https://example.com
pulse · https://example.com
GET · 3 checks · timeout 20s

  #1  ✔ up    200 OK                      118.4 ms
      dns 2.1 ms · connect 12.4 ms · tls 33.7 ms · ttfb 70.2 ms
      tls 1.3 · expires in 41 d · 93.184.216.34:443

  #2  ✔ up    200 OK                       99.1 ms
      dns 1.4 ms · connect 10.2 ms · tls 31.9 ms · ttfb 55.6 ms
      tls 1.3 · expires in 41 d · 93.184.216.34:443

  #3  ✔ up    200 OK                      104.2 ms
      dns 1.6 ms · connect 10.9 ms · tls 32.1 ms · ttfb 59.6 ms
      tls 1.3 · expires in 41 d · 93.184.216.34:443

  3 up · 0 down · avg 107.2 ms · min 99.1 ms · max 118.4 ms
```

## Features

- **Repeatable checks** — run a URL once or many times with a per-check timeout.
- **Latency breakdown** — DNS, TCP connect, TLS handshake and time-to-first-byte.
- **TLS inspection** — version, cipher, issuer, expiry and verification status.
- **Redirect tracing** — every hop, with credential stripping across origins and
  HTTPS-downgrade detection.
- **Findings** — security-relevant observations such as an expiring or
  unverifiable certificate, a weak TLS version or a redirect to another host.
- **Text or JSON** — readable by a human, parseable by a script.
- **CI-friendly** — a non-zero exit code when a check fails.
- **Terminal-aware** — color and spinner only on a TTY, honors `NO_COLOR`, and
  falls back to ASCII symbols when Unicode is unavailable.

## Install

### `go install`

```sh
go install github.com/StackZy-Lab/pulse/cmd/pulse@latest
```

### From source

```sh
git clone https://github.com/StackZy-Lab/pulse
cd pulse
make build        # produces ./pulse
```

Requires **Go 1.23** or newer.

## Quick start

```sh
# A bare host defaults to https://
pulse example.com

# Check five times with a shorter timeout
pulse -n 5 --timeout 10s https://example.com

# Machine-readable output
pulse --json https://api.example.com/health
```

If no URL is given and standard input is a terminal, `pulse` prompts for one.
When input is not a terminal (for example in a pipeline), a URL argument is
required, so scripts never hang waiting for input.

## Usage

```
pulse [flags] [url]
```

| Flag | Default | Description |
|---|---:|---|
| `-n`, `--count` | `3` | Number of checks to run. |
| `-t`, `--timeout` | `20s` | Timeout for each check. |
| `--method` | `GET` | HTTP method. |
| `-H`, `--header` | — | Add a request header (`"Name: value"`); repeatable. |
| `-d`, `--data` | — | Request body. |
| `--expect-status` | below 400 | Accepted status codes: `200`, `200,204`, `200-299` or `2xx`. |
| `--no-redirect` | `false` | Do not follow redirects. |
| `--max-body` | `0` | Read up to this many response bytes (0 = do not read the body). |
| `--insecure` | `false` | Skip TLS certificate verification and report a warning. |
| `--min-tls` | `1.2` | Minimum accepted TLS version: `1.0`, `1.1`, `1.2` or `1.3`. |
| `-o`, `--output` | `text` | Output format: `text` or `json`. |
| `--json` | `false` | Shorthand for `--output json`. |
| `--color` | `auto` | Color mode: `auto`, `always` or `never`. |
| `--ascii` | `false` | Use ASCII symbols instead of Unicode. |
| `-q`, `--quiet` | `false` | Suppress the header and progress indicator. |
| `-V`, `--version` | | Print the version and exit. |
| `-h`, `--help` | | Show help and exit. |

### Examples

```sh
# Assert a specific status and authenticate
pulse --expect-status 200 -H "Authorization: Bearer $TOKEN" https://api.example.com/health

# Inspect a server with a broken or self-signed certificate
pulse --insecure https://staging.example.com

# POST JSON and accept a 202
pulse --method POST -H "Content-Type: application/json" -d '{"ping":true}' \
      --expect-status 202 https://api.example.com/ping

# Emit JSON for a monitoring script
pulse --json -n 3 https://example.com | jq '.summary'
```

## Output

### Text

Each check is printed as it completes, so results appear immediately:

- a status line with the check number, an up/down indicator, the status or error
  reason, and the total duration;
- a per-phase latency line (DNS, connect, TLS, TTFB);
- the negotiated TLS version, certificate expiry and remote address;
- any redirect hops and security findings.

The run ends with a one-line summary of up/down counts and min/avg/max latency.

### JSON

`--json` writes a single document to stdout:

```json
{
  "url": "https://example.com",
  "method": "GET",
  "summary": { "checks": 3, "up": 3, "down": 0, "avg_ms": 107.2, "min_ms": 99.1, "max_ms": 118.4 },
  "checks": [
    {
      "number": 1,
      "up": true,
      "kind": "ok",
      "status_code": 200,
      "duration_ms": 118.4,
      "timing_ms": { "dns_ms": 2.1, "connect_ms": 12.4, "tls_ms": 33.7, "ttfb_ms": 70.2, "total_ms": 118.4 },
      "remote_addr": "93.184.216.34:443",
      "tls": { "version": "TLS 1.3", "verified": true, "days_to_expiry": 41 }
    }
  ]
}
```

All durations are in milliseconds. The `kind` field is a stable, machine-readable
outcome (`ok`, `dns_failure`, `connection_refused`, `timeout`, `tls_error`,
`status_error`, `redirect_loop`, and so on).

## Exit status

| Code | Meaning |
|---:|---|
| `0` | Every check succeeded. |
| `1` | At least one check failed (the endpoint is down, timed out, or returned an unacceptable status). |
| `2` | Invalid usage or configuration. |
| `130` | Interrupted (Ctrl-C). |

## Security

`pulse` is a **client** tool: it checks the URL you give it, so it does not
impose the private-network restrictions a multi-tenant monitoring server needs.
Point it at an internal host if you want to. The behaviors worth understanding:

- **Certificates are verified by default.** `--insecure` disables verification
  and is meant for inspecting misconfigured servers; every such check carries a
  warning finding. An unverifiable certificate in the default mode fails the
  check.
- **The response body is not downloaded by default.** `--max-body` reads up to a
  byte limit if you need a size. This keeps checks fast and avoids pulling large
  or unexpected payloads.
- **Redirect credentials are stripped.** When a redirect changes origin, the
  request headers you set (and `Authorization`, `Cookie`, `Proxy-Authorization`)
  are removed before the next hop, and a warning finding is recorded.
  Cross-origin redirects that would resend a request body are refused.
- **URLs with embedded credentials are rejected** so secrets do not end up in
  shell history or logs.

Use `--insecure` and internal targets only on systems and networks you are
authorized to test. See [SECURITY.md](SECURITY.md) for how to report a
vulnerability.

## Architecture

```
cmd/pulse/          CLI entry point: signal handling, exit codes
internal/cli/       flag parsing, prompt, run loop, exit codes
internal/probe/     the probing engine (HTTP, timing, TLS, redirects, errors)
internal/report/    text and JSON renderers, run statistics
internal/term/      TTY/color detection, symbol sets, spinner
```

The engine (`internal/probe`) has no opinion about presentation or process
lifecycle: `Prober.Check` takes a `Request`, returns a `Result`, and never
returns an error — a failed check is data. Everything user-facing lives in the
other packages, which keeps the engine easy to embed and test.

`pulse` was inspired by an internal StackZy checker, but is an independent
project: the multi-tenant concerns (worker pools, broker integration, SSRF
policies, metrics endpoints) were intentionally left behind, and the probing
core was redesigned around a single, well-documented public API.

## Development

```sh
make build     # build ./pulse
make test      # go test -race ./...
make vet       # go vet ./...
make fmt       # gofmt -w .
make install   # go install ./cmd/pulse
```

Always run tests with `-race`: the request tracer collects timings from the
resolver, dialer and handshake goroutines.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © StackZy-Lab
