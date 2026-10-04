package cli

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/StackZy-Lab/pulse/internal/probe"
)

type action int

const (
	actionRun action = iota
	actionHelp
	actionVersion
)

// options holds the parsed command-line configuration.
type options struct {
	url        string
	count      int
	timeout    time.Duration
	method     string
	headers    map[string]string
	body       string
	expect     string
	noRedirect bool
	insecure   bool
	minTLS     string
	maxBody    int64
	output     string
	color      string
	ascii      bool
	quiet      bool
}

// parse turns raw arguments into options. A returned action of actionHelp or
// actionVersion short-circuits the run.
func parse(args []string) (options, action, error) {
	var (
		opts        options
		rawHeaders  headerList
		jsonOutput  bool
		showVersion bool
	)

	fs := flag.NewFlagSet("pulse", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	fs.IntVar(&opts.count, "count", 3, "")
	fs.IntVar(&opts.count, "n", 3, "")
	fs.DurationVar(&opts.timeout, "timeout", 20*time.Second, "")
	fs.DurationVar(&opts.timeout, "t", 20*time.Second, "")
	fs.StringVar(&opts.method, "method", "GET", "")
	fs.Var(&rawHeaders, "header", "")
	fs.Var(&rawHeaders, "H", "")
	fs.StringVar(&opts.body, "data", "", "")
	fs.StringVar(&opts.body, "d", "", "")
	fs.StringVar(&opts.expect, "expect-status", "", "")
	fs.BoolVar(&opts.noRedirect, "no-redirect", false, "")
	fs.BoolVar(&opts.insecure, "insecure", false, "")
	fs.StringVar(&opts.minTLS, "min-tls", "1.2", "")
	fs.Int64Var(&opts.maxBody, "max-body", 0, "")
	fs.StringVar(&opts.output, "output", "text", "")
	fs.StringVar(&opts.output, "o", "text", "")
	fs.BoolVar(&jsonOutput, "json", false, "")
	fs.StringVar(&opts.color, "color", "auto", "")
	fs.BoolVar(&opts.ascii, "ascii", false, "")
	fs.BoolVar(&opts.quiet, "quiet", false, "")
	fs.BoolVar(&opts.quiet, "q", false, "")
	fs.BoolVar(&showVersion, "version", false, "")
	fs.BoolVar(&showVersion, "V", false, "")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return opts, actionHelp, nil
		}
		return opts, actionRun, err
	}
	if showVersion {
		return opts, actionVersion, nil
	}

	switch len(fs.Args()) {
	case 0:
	case 1:
		opts.url = strings.TrimSpace(fs.Args()[0])
	default:
		return opts, actionRun, fmt.Errorf("expected a single URL, got %d arguments", len(fs.Args()))
	}

	if jsonOutput {
		opts.output = "json"
	}
	switch opts.output {
	case "text", "json":
	default:
		return opts, actionRun, fmt.Errorf("unknown output format %q: use text or json", opts.output)
	}
	switch opts.color {
	case "auto", "always", "never":
	default:
		return opts, actionRun, fmt.Errorf("unknown color mode %q: use auto, always or never", opts.color)
	}
	if opts.count < 1 {
		return opts, actionRun, errors.New("count must be at least 1")
	}
	if opts.timeout <= 0 {
		return opts, actionRun, errors.New("timeout must be greater than zero")
	}
	if opts.maxBody < 0 {
		return opts, actionRun, errors.New("max-body cannot be negative")
	}

	headers, err := parseHeaderFlags(rawHeaders)
	if err != nil {
		return opts, actionRun, err
	}
	opts.headers = headers
	return opts, actionRun, nil
}

// proberConfig builds the engine configuration, validating the options that
// only surface once converted.
func (o options) proberConfig() (probe.Config, error) {
	matcher, err := probe.ParseStatusMatcher(o.expect)
	if err != nil {
		return probe.Config{}, err
	}
	minVersion, err := parseTLSVersion(o.minTLS)
	if err != nil {
		return probe.Config{}, err
	}
	return probe.Config{
		Timeout:          o.timeout,
		DisableRedirects: o.noRedirect,
		ExpectStatus:     matcher,
		Insecure:         o.insecure,
		MinTLSVersion:    minVersion,
		MaxBodyBytes:     o.maxBody,
		UserAgent:        "pulse/" + Version,
	}, nil
}

// headerList accumulates repeatable --header flags.
type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }

func (h *headerList) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func parseHeaderFlags(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	headers := make(map[string]string, len(raw))
	for _, item := range raw {
		name, value, ok := strings.Cut(item, ":")
		if !ok {
			return nil, fmt.Errorf("invalid header %q: expected \"Name: value\"", item)
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" {
			return nil, fmt.Errorf("invalid header %q: empty name", item)
		}
		if existing, ok := headers[name]; ok && existing != "" {
			headers[name] = existing + ", " + value
			continue
		}
		headers[name] = value
	}
	return headers, nil
}

func parseTLSVersion(spec string) (uint16, error) {
	switch strings.ToLower(strings.TrimSpace(spec)) {
	case "1", "1.0", "tls1", "tls1.0":
		return tls.VersionTLS10, nil
	case "1.1", "tls1.1":
		return tls.VersionTLS11, nil
	case "1.2", "tls1.2":
		return tls.VersionTLS12, nil
	case "1.3", "tls1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("invalid TLS version %q: use 1.0, 1.1, 1.2 or 1.3", spec)
	}
}
