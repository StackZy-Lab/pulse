package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/StackZy-Lab/pulse/internal/probe"
	"github.com/StackZy-Lab/pulse/internal/term"
)

func sampleReport() Report {
	now := time.Now()
	return Report{
		URL:     "https://example.com",
		Method:  "GET",
		Checks:  2,
		Timeout: 20 * time.Second,
		Results: []*probe.Result{
			{
				URL:        "https://example.com",
				FinalURL:   "https://example.com/",
				Method:     "GET",
				StatusCode: 200,
				Up:         true,
				Kind:       probe.KindOK,
				StartedAt:  now,
				Duration:   118 * time.Millisecond,
				Timing: probe.Timing{
					DNS:     2 * time.Millisecond,
					Connect: 12 * time.Millisecond,
					TLS:     33 * time.Millisecond,
					Server:  70 * time.Millisecond,
					Total:   118 * time.Millisecond,
				},
				RemoteAddr: "93.184.216.34:443",
				TLS: &probe.TLSInfo{
					Version:      "TLS 1.3",
					NotAfter:     now.Add(41 * 24 * time.Hour),
					DaysToExpiry: 41,
					Verified:     true,
				},
				Redirects: []probe.Redirect{{From: "https://example.com", To: "https://example.com/", StatusCode: 301}},
				Findings: []probe.Finding{{
					Code:     probe.FindingTLSExpiringSoon,
					Severity: probe.SeverityWarning,
					Message:  "certificate expires in 9 days",
				}},
			},
			{
				URL:      "https://example.com",
				Method:   "GET",
				Up:       false,
				Kind:     probe.KindConnectionRefused,
				Error:    "dial tcp 127.0.0.1:9: connect: connection refused",
				Duration: 4 * time.Millisecond,
				Timing:   probe.Timing{Total: 4 * time.Millisecond},
			},
		},
	}
}

func TestTextReport(t *testing.T) {
	rep := sampleReport()

	var buf bytes.Buffer
	Text(&buf, rep, Options{Style: term.NewStyle(false), Symbols: term.ASCIISymbols()})
	out := buf.String()

	for _, want := range []string{
		"pulse", "https://example.com", "2 checks", "timeout 20s",
		"#1", "up", "200 OK", "ttfb",
		"down", "connection refused",
		"1 up", "1 down",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q\n---\n%s", want, out)
		}
	}
}

func TestTextReportHasNoEscapesWhenDisabled(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sampleReport(), Options{Style: term.NewStyle(false), Symbols: term.ASCIISymbols()})
	if strings.Contains(buf.String(), "\x1b[") {
		t.Error("output contains ANSI escapes with color disabled")
	}
}

func TestTextReportHasEscapesWhenEnabled(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sampleReport(), Options{Style: term.NewStyle(true), Symbols: term.UnicodeSymbols()})
	if !strings.Contains(buf.String(), "\x1b[") {
		t.Error("output has no ANSI escapes with color enabled")
	}
}

func TestSummary(t *testing.T) {
	stats := Summarize(sampleReport().Results)
	if stats.Checks != 2 || stats.Up != 1 || stats.Down != 1 {
		t.Errorf("stats = %+v, want 2 checks, 1 up, 1 down", stats)
	}
	if stats.Min != 4*time.Millisecond || stats.Max != 118*time.Millisecond {
		t.Errorf("min/max = %v/%v, want 4ms/118ms", stats.Min, stats.Max)
	}
	wantAvg := (118*time.Millisecond + 4*time.Millisecond) / 2
	if stats.Avg != wantAvg {
		t.Errorf("avg = %v, want %v", stats.Avg, wantAvg)
	}
}

func TestJSONReport(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleReport()); err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var doc struct {
		URL     string `json:"url"`
		Summary struct {
			Checks int `json:"checks"`
			Up     int `json:"up"`
			Down   int `json:"down"`
		} `json:"summary"`
		Checks []struct {
			Number     int     `json:"number"`
			Up         bool    `json:"up"`
			Kind       string  `json:"kind"`
			DurationMS float64 `json:"duration_ms"`
			TLS        *struct {
				Version string `json:"version"`
			} `json:"tls"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if doc.URL != "https://example.com" {
		t.Errorf("url = %q", doc.URL)
	}
	if doc.Summary.Checks != 2 || doc.Summary.Up != 1 || doc.Summary.Down != 1 {
		t.Errorf("summary = %+v", doc.Summary)
	}
	if len(doc.Checks) != 2 {
		t.Fatalf("len(checks) = %d, want 2", len(doc.Checks))
	}
	if doc.Checks[0].DurationMS <= 0 {
		t.Errorf("duration_ms = %v, want > 0", doc.Checks[0].DurationMS)
	}
	if doc.Checks[0].TLS == nil || doc.Checks[0].TLS.Version != "TLS 1.3" {
		t.Errorf("tls = %+v, want TLS 1.3", doc.Checks[0].TLS)
	}
	if doc.Checks[1].Kind != string(probe.KindConnectionRefused) {
		t.Errorf("kind = %q, want %q", doc.Checks[1].Kind, probe.KindConnectionRefused)
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		in    time.Duration
		micro string
		want  string
	}{
		{500 * time.Microsecond, "µs", "500 µs"},
		{1500 * time.Microsecond, "µs", "1.5 ms"},
		{250 * time.Millisecond, "µs", "250.0 ms"},
		{1500 * time.Millisecond, "µs", "1.50 s"},
		{500 * time.Microsecond, "us", "500 us"},
	}
	for _, tt := range tests {
		if got := FormatDuration(tt.in, tt.micro); got != tt.want {
			t.Errorf("FormatDuration(%v, %q) = %q, want %q", tt.in, tt.micro, got, tt.want)
		}
	}
}
