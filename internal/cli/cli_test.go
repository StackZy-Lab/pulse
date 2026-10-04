package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseFlags(t *testing.T) {
	opts, act, err := parse([]string{"-n", "5", "--timeout", "10s", "-H", "X-A: 1", "example.com"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if act != actionRun {
		t.Errorf("action = %v, want actionRun", act)
	}
	if opts.count != 5 {
		t.Errorf("count = %d, want 5", opts.count)
	}
	if opts.timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", opts.timeout)
	}
	if opts.url != "example.com" {
		t.Errorf("url = %q, want example.com", opts.url)
	}
	if opts.headers["X-A"] != "1" {
		t.Errorf("headers = %v, want X-A: 1", opts.headers)
	}
}

func TestParseActions(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want action
	}{
		{[]string{"--help"}, actionHelp},
		{[]string{"-h"}, actionHelp},
		{[]string{"--version"}, actionVersion},
		{[]string{"-V"}, actionVersion},
	} {
		_, act, err := parse(tt.args)
		if err != nil {
			t.Fatalf("parse(%v): %v", tt.args, err)
		}
		if act != tt.want {
			t.Errorf("parse(%v) action = %v, want %v", tt.args, act, tt.want)
		}
	}
}

func TestParseJSONShorthand(t *testing.T) {
	opts, _, err := parse([]string{"--json", "example.com"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if opts.output != "json" {
		t.Errorf("output = %q, want json", opts.output)
	}
}

func TestParseErrors(t *testing.T) {
	tests := [][]string{
		{"--unknown"},
		{"-n", "0", "example.com"},
		{"--timeout", "0s", "example.com"},
		{"-o", "xml", "example.com"},
		{"--color", "rainbow", "example.com"},
		{"--max-body", "-1", "example.com"},
		{"-H", "no-colon", "example.com"},
		{"a.example.com", "b.example.com"},
	}
	for _, args := range tests {
		if _, _, err := parse(args); err == nil {
			t.Errorf("parse(%v) = nil error, want error", args)
		}
	}
}

func TestParseTLSVersion(t *testing.T) {
	tests := map[string]uint16{
		"1.0":    tls.VersionTLS10,
		"1.1":    tls.VersionTLS11,
		"1.2":    tls.VersionTLS12,
		"1.3":    tls.VersionTLS13,
		"tls1.2": tls.VersionTLS12,
	}
	for spec, want := range tests {
		got, err := parseTLSVersion(spec)
		if err != nil {
			t.Fatalf("parseTLSVersion(%q): %v", spec, err)
		}
		if got != want {
			t.Errorf("parseTLSVersion(%q) = %#x, want %#x", spec, got, want)
		}
	}
	if _, err := parseTLSVersion("2.0"); err == nil {
		t.Error("parseTLSVersion(2.0) = nil error, want error")
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "example.com", want: "https://example.com"},
		{in: "http://example.com/path", want: "http://example.com/path"},
		{in: "  https://example.com  ", want: "https://example.com"},
		{in: "", wantErr: true},
		{in: "ftp://example.com", wantErr: true},
		{in: "https://", wantErr: true},
		{in: "https://user:pass@example.com", wantErr: true},
	}
	for _, tt := range tests {
		got, err := normalizeURL(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("normalizeURL(%q) = %q, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeURL(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("normalizeURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRunHelpAndVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"--help"}, IO{In: strings.NewReader(""), Out: &out, Err: &errOut})
	if code != ExitOK {
		t.Errorf("--help exit = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Errorf("--help output = %q, want usage text", out.String())
	}

	out.Reset()
	code = Run(context.Background(), []string{"--version"}, IO{In: strings.NewReader(""), Out: &out, Err: &errOut})
	if code != ExitOK {
		t.Errorf("--version exit = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(out.String(), Version) {
		t.Errorf("--version output = %q, want it to contain %q", out.String(), Version)
	}
}

func TestRunRequiresURLWhenNotInteractive(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), nil, IO{
		In: strings.NewReader("example.com\n"), Out: &out, Err: &errOut, InIsTTY: false,
	})
	if code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut.String(), "no URL provided") {
		t.Errorf("stderr = %q, want a no-URL error", errOut.String())
	}
}

func TestRunInvalidFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"--nope"}, IO{In: strings.NewReader(""), Out: &out, Err: &errOut})
	if code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
}

func TestRunPromptsWhenInteractive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"-n", "1"}, IO{
		In:       strings.NewReader(srv.URL + "\n"),
		Out:      &out,
		Err:      &errOut,
		InIsTTY:  true,
		OutIsTTY: false,
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, ExitOK, errOut.String())
	}
	if !strings.Contains(errOut.String(), "Enter a URL") {
		t.Errorf("stderr = %q, want the prompt", errOut.String())
	}
	if !strings.Contains(out.String(), "1 up") {
		t.Errorf("stdout = %q, want a passing summary", out.String())
	}
}

func TestRunReportsUpAndDown(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	t.Run("up", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), []string{"-n", "2", "--color", "never", "--ascii", ok.URL},
			IO{In: strings.NewReader(""), Out: &out, Err: &errOut})
		if code != ExitOK {
			t.Fatalf("exit = %d, want %d", code, ExitOK)
		}
		if !strings.Contains(out.String(), "2 up") {
			t.Errorf("stdout = %q, want 2 up", out.String())
		}
	})

	t.Run("down", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), []string{"-n", "1", "--color", "never", "--ascii", bad.URL},
			IO{In: strings.NewReader(""), Out: &out, Err: &errOut})
		if code != ExitDown {
			t.Fatalf("exit = %d, want %d", code, ExitDown)
		}
		if !strings.Contains(out.String(), "1 down") {
			t.Errorf("stdout = %q, want 1 down", out.String())
		}
	})
}

func TestRunJSONOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"--json", "-n", "1", srv.URL},
		IO{In: strings.NewReader(""), Out: &out, Err: &errOut})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, ExitOK, errOut.String())
	}

	var doc struct {
		Summary struct {
			Up int `json:"up"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
	}
	if doc.Summary.Up != 1 {
		t.Errorf("summary.up = %d, want 1", doc.Summary.Up)
	}
}
