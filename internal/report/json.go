package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/StackZy-Lab/pulse/internal/probe"
)

// The JSON shape is a dedicated presentation model rather than the engine's
// structs, so durations are reported in milliseconds as plain numbers and the
// output stays stable even if the engine's internal types change.

type jsonReport struct {
	URL     string      `json:"url"`
	Method  string      `json:"method"`
	Summary jsonSummary `json:"summary"`
	Checks  []jsonCheck `json:"checks"`
}

type jsonSummary struct {
	Checks int     `json:"checks"`
	Up     int     `json:"up"`
	Down   int     `json:"down"`
	AvgMS  float64 `json:"avg_ms"`
	MinMS  float64 `json:"min_ms"`
	MaxMS  float64 `json:"max_ms"`
}

type jsonCheck struct {
	Number     int            `json:"number"`
	Up         bool           `json:"up"`
	Kind       string         `json:"kind"`
	Error      string         `json:"error,omitempty"`
	URL        string         `json:"url"`
	FinalURL   string         `json:"final_url,omitempty"`
	Method     string         `json:"method"`
	StatusCode int            `json:"status_code,omitempty"`
	StartedAt  string         `json:"started_at"`
	DurationMS float64        `json:"duration_ms"`
	Timing     jsonTiming     `json:"timing_ms"`
	RemoteAddr string         `json:"remote_addr,omitempty"`
	BodyBytes  int64          `json:"body_bytes,omitempty"`
	TLS        *jsonTLS       `json:"tls,omitempty"`
	Redirects  []jsonRedirect `json:"redirects,omitempty"`
	Findings   []jsonFinding  `json:"findings,omitempty"`
}

type jsonTiming struct {
	DNSMS     float64 `json:"dns_ms"`
	ConnectMS float64 `json:"connect_ms"`
	TLSMS     float64 `json:"tls_ms"`
	TTFBMS    float64 `json:"ttfb_ms"`
	TotalMS   float64 `json:"total_ms"`
}

type jsonTLS struct {
	Version      string   `json:"version"`
	CipherSuite  string   `json:"cipher_suite,omitempty"`
	ServerName   string   `json:"server_name,omitempty"`
	Subject      string   `json:"subject,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
	DNSNames     []string `json:"dns_names,omitempty"`
	NotBefore    string   `json:"not_before,omitempty"`
	NotAfter     string   `json:"not_after,omitempty"`
	DaysToExpiry int      `json:"days_to_expiry"`
	ChainLength  int      `json:"chain_length"`
	Verified     bool     `json:"verified"`
	Error        string   `json:"error,omitempty"`
}

type jsonRedirect struct {
	From       string `json:"from"`
	To         string `json:"to"`
	StatusCode int    `json:"status_code"`
}

type jsonFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// JSON writes the whole report as a single JSON document.
func JSON(w io.Writer, rep Report) error {
	stats := Summarize(rep.Results)
	out := jsonReport{
		URL:    rep.URL,
		Method: rep.Method,
		Summary: jsonSummary{
			Checks: stats.Checks,
			Up:     stats.Up,
			Down:   stats.Down,
			AvgMS:  msOf(stats.Avg),
			MinMS:  msOf(stats.Min),
			MaxMS:  msOf(stats.Max),
		},
		Checks: make([]jsonCheck, 0, len(rep.Results)),
	}
	for i, res := range rep.Results {
		out.Checks = append(out.Checks, toJSONCheck(i+1, res))
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

func toJSONCheck(number int, res *probe.Result) jsonCheck {
	check := jsonCheck{
		Number:     number,
		Up:         res.Up,
		Kind:       string(res.Kind),
		Error:      res.Error,
		URL:        res.URL,
		FinalURL:   res.FinalURL,
		Method:     res.Method,
		StatusCode: res.StatusCode,
		StartedAt:  res.StartedAt.Format(time.RFC3339Nano),
		DurationMS: msOf(res.Duration),
		Timing: jsonTiming{
			DNSMS:     msOf(res.Timing.DNS),
			ConnectMS: msOf(res.Timing.Connect),
			TLSMS:     msOf(res.Timing.TLS),
			TTFBMS:    msOf(res.Timing.Server),
			TotalMS:   msOf(res.Timing.Total),
		},
		RemoteAddr: res.RemoteAddr,
		BodyBytes:  res.BodySize,
	}
	if res.TLS != nil {
		check.TLS = &jsonTLS{
			Version:      res.TLS.Version,
			CipherSuite:  res.TLS.CipherSuite,
			ServerName:   res.TLS.ServerName,
			Subject:      res.TLS.Subject,
			Issuer:       res.TLS.Issuer,
			DNSNames:     res.TLS.DNSNames,
			DaysToExpiry: res.TLS.DaysToExpiry,
			ChainLength:  res.TLS.ChainLength,
			Verified:     res.TLS.Verified,
			Error:        res.TLS.Error,
		}
		if !res.TLS.NotBefore.IsZero() {
			check.TLS.NotBefore = res.TLS.NotBefore.Format(time.RFC3339)
		}
		if !res.TLS.NotAfter.IsZero() {
			check.TLS.NotAfter = res.TLS.NotAfter.Format(time.RFC3339)
		}
	}
	for _, hop := range res.Redirects {
		check.Redirects = append(check.Redirects, jsonRedirect(hop))
	}
	for _, f := range res.Findings {
		check.Findings = append(check.Findings, jsonFinding{Code: f.Code, Severity: string(f.Severity), Message: f.Message})
	}
	return check
}

func msOf(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
