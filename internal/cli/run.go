// Package cli implements the pulse command line: flag parsing, the interactive
// prompt, running the checks and rendering the report.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/StackZy-Lab/pulse/internal/probe"
	"github.com/StackZy-Lab/pulse/internal/report"
	"github.com/StackZy-Lab/pulse/internal/term"
)

// Exit codes returned by Run.
const (
	ExitOK          = 0   // every check succeeded
	ExitDown        = 1   // at least one check failed
	ExitUsage       = 2   // the command was invoked incorrectly
	ExitInterrupted = 130 // the run was interrupted (128 + SIGINT)
)

// IO bundles the streams and terminal properties the command needs. Passing
// them explicitly keeps Run testable and main trivial.
type IO struct {
	In       io.Reader
	Out      io.Writer
	Err      io.Writer
	InIsTTY  bool
	OutIsTTY bool
	ErrIsTTY bool
}

// Run executes the command and returns a process exit code. The context can be
// cancelled to stop an in-flight check (for example on SIGINT).
func Run(ctx context.Context, args []string, streams IO) int {
	opts, act, err := parse(args)
	switch act {
	case actionHelp:
		fmt.Fprint(streams.Out, helpText)
		return ExitOK
	case actionVersion:
		fmt.Fprintf(streams.Out, "pulse %s\n", Version)
		return ExitOK
	}
	if err != nil {
		fmt.Fprintf(streams.Err, "pulse: %v\n\n%s", err, helpText)
		return ExitUsage
	}

	target, err := resolveURL(opts, streams)
	if err != nil {
		fmt.Fprintf(streams.Err, "pulse: %v\n", err)
		return ExitUsage
	}

	cfg, err := opts.proberConfig()
	if err != nil {
		fmt.Fprintf(streams.Err, "pulse: %v\n", err)
		return ExitUsage
	}

	style := term.NewStyle(term.ColorEnabled(streams.Out, opts.color))
	unicode := !opts.ascii && term.UnicodeEnabled()
	symbols := term.ASCIISymbols()
	if unicode {
		symbols = term.UnicodeSymbols()
	}

	prober := probe.NewProber(cfg)
	request := probe.Request{
		URL:     target,
		Method:  opts.method,
		Headers: opts.headers,
		Body:    opts.body,
	}
	rep := report.Report{
		URL:     target,
		Method:  strings.ToUpper(strings.TrimSpace(opts.method)),
		Checks:  opts.count,
		Timeout: opts.timeout,
		Results: make([]*probe.Result, 0, opts.count),
	}
	renderOpts := report.Options{Style: style, Symbols: symbols}
	jsonMode := opts.output == "json"

	if !opts.quiet && !jsonMode {
		report.Header(streams.Out, rep, renderOpts)
	}

	spinner := term.NewSpinner(streams.Err, !opts.quiet && streams.ErrIsTTY, term.SpinnerFrames(unicode))

	exit := ExitOK
	for i := 1; i <= opts.count; i++ {
		spinner.Start(fmt.Sprintf("checking %s (%d/%d)", target, i, opts.count))

		checkCtx, cancel := context.WithTimeout(ctx, opts.timeout)
		result := prober.Check(checkCtx, request)
		cancel()
		spinner.Stop()

		if ctx.Err() != nil {
			fmt.Fprintln(streams.Err, "pulse: interrupted")
			return ExitInterrupted
		}

		rep.Results = append(rep.Results, result)
		if !result.Up {
			exit = ExitDown
		}
		if !jsonMode {
			report.Check(streams.Out, i, opts.count, result, renderOpts)
		}
	}

	if jsonMode {
		if err := report.JSON(streams.Out, rep); err != nil {
			fmt.Fprintf(streams.Err, "pulse: %v\n", err)
			return ExitUsage
		}
		return exit
	}
	if !opts.quiet {
		report.Summary(streams.Out, rep, renderOpts)
	}
	return exit
}

// resolveURL returns the target from the argument, or prompts for it when the
// input is an interactive terminal.
func resolveURL(opts options, streams IO) (string, error) {
	if opts.url != "" {
		return normalizeURL(opts.url)
	}
	if !streams.InIsTTY {
		return "", errors.New("no URL provided (pass a URL argument)")
	}

	fmt.Fprint(streams.Err, "Enter a URL to check: ")
	line, err := bufio.NewReader(streams.In).ReadString('\n')
	if raw := strings.TrimSpace(line); raw != "" {
		return normalizeURL(raw)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("reading URL: %w", err)
	}
	return "", errors.New("no URL provided")
}

// normalizeURL trims the input, defaults a missing scheme to https, and
// validates the result so the user gets a clear error before any check runs.
func normalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("no URL provided")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	switch parsed.Scheme {
	case "http", "https":
	default:
		return "", fmt.Errorf("unsupported URL scheme %q: use http or https", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("invalid URL %q: missing host", raw)
	}
	if parsed.User != nil {
		return "", errors.New("URLs with embedded credentials are not supported")
	}
	return parsed.String(), nil
}
