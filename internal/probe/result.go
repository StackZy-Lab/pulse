package probe

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Severity classifies a Finding.
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
)

// Finding codes. A finding is a security- or operations-relevant observation
// that does not by itself make a check fail.
const (
	FindingHTTPSDowngrade   = "https_downgrade"
	FindingHostChange       = "host_change"
	FindingTLSExpiringSoon  = "tls_expiring_soon"
	FindingWeakTLSVersion   = "weak_tls_version"
	FindingCertNameMismatch = "cert_name_mismatch"
	FindingInsecureTLS      = "insecure_tls"
	FindingTLSVerifyFailed  = "tls_verification_failed"
)

// Finding is a single observation attached to a Result.
type Finding struct {
	Code     string
	Severity Severity
	Message  string
}

// Timing breaks a check's latency into phases. The components do not
// necessarily add up to Total: time spent between phases, and across redirect
// hops, is counted in Total only.
type Timing struct {
	DNS     time.Duration // name resolution
	Connect time.Duration // TCP connect (and any proxy tunnel)
	TLS     time.Duration // TLS handshake
	Server  time.Duration // request written until first response byte (TTFB)
	Total   time.Duration
}

// TLSInfo describes the TLS session observed during a check. It is populated
// from the negotiated connection, whether or not verification succeeded.
type TLSInfo struct {
	Version      string
	CipherSuite  string
	ServerName   string
	Subject      string
	Issuer       string
	DNSNames     []string
	NotBefore    time.Time
	NotAfter     time.Time
	DaysToExpiry int
	ChainLength  int
	// Verified reports whether the certificate chain and hostname verified
	// against the system trust store.
	Verified bool
	// Error is the verification error, if any. It is only set when the check
	// ran with certificate verification disabled.
	Error string
}

// Redirect is one followed redirect hop.
type Redirect struct {
	From       string
	To         string
	StatusCode int
}

// Result is the outcome of a single check. Check always returns a non-nil
// Result, including when the request itself failed.
type Result struct {
	// URL is the checked URL and FinalURL the URL of the final response once
	// redirects have been followed.
	URL      string
	FinalURL string
	Method   string

	StatusCode int
	Up         bool
	Kind       ErrorKind
	Error      string

	StartedAt time.Time
	Duration  time.Duration
	Timing    Timing

	RemoteAddr    string
	BodySize      int64
	BodyTruncated bool

	TLS       *TLSInfo
	Redirects []Redirect
	Findings  []Finding
}

// StatusText returns the numeric status followed by its standard reason
// phrase, for example "200 OK". It returns "" when no response was received.
func (r *Result) StatusText() string {
	if r.StatusCode == 0 {
		return ""
	}
	if text := http.StatusText(r.StatusCode); text != "" {
		return fmt.Sprintf("%d %s", r.StatusCode, text)
	}
	return strconv.Itoa(r.StatusCode)
}

// addFinding appends a finding unless one with the same code is already
// present, so a value seen on several redirect hops is reported once.
func (r *Result) addFinding(f Finding) {
	for _, existing := range r.Findings {
		if existing.Code == f.Code {
			return
		}
	}
	r.Findings = append(r.Findings, f)
}
