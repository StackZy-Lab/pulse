package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{Timeout: 5 * time.Second}
}

func runCheck(t *testing.T, p *Prober, req Request) *Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res := p.Check(ctx, req)
	if res == nil {
		t.Fatal("Check returned a nil result")
	}
	return res
}

func hasFinding(res *Result, code string) bool {
	for _, f := range res.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestCheckSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	defer srv.Close()

	res := runCheck(t, NewProber(testConfig()), Request{URL: srv.URL})

	if !res.Up {
		t.Fatalf("Up = false, kind = %s, error = %q", res.Kind, res.Error)
	}
	if res.Kind != KindOK {
		t.Errorf("Kind = %s, want %s", res.Kind, KindOK)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", res.StatusCode)
	}
	if res.Method != http.MethodGet {
		t.Errorf("Method = %q, want GET", res.Method)
	}
	if res.Timing.Total <= 0 {
		t.Errorf("Timing.Total = %v, want > 0", res.Timing.Total)
	}
	if res.RemoteAddr == "" {
		t.Error("RemoteAddr is empty")
	}
}

func TestCheckSendsRequest(t *testing.T) {
	type captured struct {
		method string
		header string
		body   string
	}
	got := make(chan captured, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- captured{method: r.Method, header: r.Header.Get("X-Test"), body: string(body)}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := runCheck(t, NewProber(testConfig()), Request{
		URL:     srv.URL,
		Method:  "POST",
		Headers: map[string]string{"X-Test": "yes"},
		Body:    "payload",
	})
	if !res.Up {
		t.Fatalf("Up = false, kind = %s", res.Kind)
	}

	select {
	case c := <-got:
		if c.method != http.MethodPost {
			t.Errorf("method = %q, want POST", c.method)
		}
		if c.header != "yes" {
			t.Errorf("X-Test = %q, want yes", c.header)
		}
		if c.body != "payload" {
			t.Errorf("body = %q, want payload", c.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not receive the request")
	}
}

func TestCheckStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	res := runCheck(t, NewProber(testConfig()), Request{URL: srv.URL})

	if res.Up {
		t.Fatal("Up = true, want false for 404")
	}
	if res.Kind != KindStatusError {
		t.Errorf("Kind = %s, want %s", res.Kind, KindStatusError)
	}
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want 404", res.StatusCode)
	}
}

func TestCheckExpectStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	matcher, err := ParseStatusMatcher("404")
	if err != nil {
		t.Fatalf("ParseStatusMatcher: %v", err)
	}
	cfg := testConfig()
	cfg.ExpectStatus = matcher

	res := runCheck(t, NewProber(cfg), Request{URL: srv.URL})
	if !res.Up {
		t.Fatalf("Up = false, kind = %s, want 404 to be accepted", res.Kind)
	}
}

func TestCheckFollowsRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	res := runCheck(t, NewProber(testConfig()), Request{URL: redirector.URL})

	if !res.Up {
		t.Fatalf("Up = false, kind = %s", res.Kind)
	}
	if len(res.Redirects) != 1 {
		t.Fatalf("len(Redirects) = %d, want 1", len(res.Redirects))
	}
	if res.Redirects[0].StatusCode != http.StatusFound {
		t.Errorf("redirect status = %d, want 302", res.Redirects[0].StatusCode)
	}
	if res.FinalURL != target.URL {
		t.Errorf("FinalURL = %q, want %q", res.FinalURL, target.URL)
	}
}

func TestCheckRedirectsDisabled(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusMovedPermanently)
	}))
	defer redirector.Close()

	cfg := testConfig()
	cfg.DisableRedirects = true

	res := runCheck(t, NewProber(cfg), Request{URL: redirector.URL})

	if len(res.Redirects) != 0 {
		t.Errorf("len(Redirects) = %d, want 0 when redirects are disabled", len(res.Redirects))
	}
	if res.StatusCode != http.StatusMovedPermanently {
		t.Errorf("StatusCode = %d, want 301", res.StatusCode)
	}
}

func TestCheckHTTPSDowngradeFinding(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer plain.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer secure.Close()

	cfg := testConfig()
	cfg.Insecure = true

	res := runCheck(t, NewProber(cfg), Request{URL: secure.URL})
	if !hasFinding(res, FindingHTTPSDowngrade) {
		t.Errorf("findings = %+v, want %s", res.Findings, FindingHTTPSDowngrade)
	}
}

func TestCheckTLSVerificationFailsByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := runCheck(t, NewProber(testConfig()), Request{URL: srv.URL})

	if res.Up {
		t.Fatal("Up = true for a self-signed certificate; verification should fail by default")
	}
	if res.Kind != KindTLSError {
		t.Errorf("Kind = %s, want %s", res.Kind, KindTLSError)
	}
}

func TestCheckTLSInsecure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.Insecure = true

	res := runCheck(t, NewProber(cfg), Request{URL: srv.URL})

	if !res.Up {
		t.Fatalf("Up = false, kind = %s, want up in insecure mode", res.Kind)
	}
	if res.TLS == nil {
		t.Fatal("TLS info is nil")
	}
	if !hasFinding(res, FindingInsecureTLS) {
		t.Errorf("findings = %+v, want %s", res.Findings, FindingInsecureTLS)
	}
	if !hasFinding(res, FindingTLSVerifyFailed) {
		t.Errorf("findings = %+v, want %s", res.Findings, FindingTLSVerifyFailed)
	}
}

func TestCheckMinTLSVersion(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.Insecure = true
	cfg.MinTLSVersion = tls.VersionTLS13

	res := runCheck(t, NewProber(cfg), Request{URL: srv.URL})
	if !res.Up {
		t.Fatalf("Up = false, kind = %s", res.Kind)
	}
	if res.TLS == nil || res.TLS.Version != "TLS 1.3" {
		t.Errorf("TLS version = %+v, want TLS 1.3", res.TLS)
	}
}

func TestCheckBodySize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "0123456789")
	}))
	defer srv.Close()

	t.Run("truncated", func(t *testing.T) {
		cfg := testConfig()
		cfg.MaxBodyBytes = 4
		res := runCheck(t, NewProber(cfg), Request{URL: srv.URL})
		if res.BodySize != 4 || !res.BodyTruncated {
			t.Errorf("BodySize = %d, truncated = %v, want 4, true", res.BodySize, res.BodyTruncated)
		}
	})

	t.Run("full", func(t *testing.T) {
		cfg := testConfig()
		cfg.MaxBodyBytes = 1024
		res := runCheck(t, NewProber(cfg), Request{URL: srv.URL})
		if res.BodySize != 10 || res.BodyTruncated {
			t.Errorf("BodySize = %d, truncated = %v, want 10, false", res.BodySize, res.BodyTruncated)
		}
	})

	t.Run("unread by default", func(t *testing.T) {
		res := runCheck(t, NewProber(testConfig()), Request{URL: srv.URL})
		if res.BodySize != 0 {
			t.Errorf("BodySize = %d, want 0 when the body is not read", res.BodySize)
		}
	})
}

func TestCheckConnectionRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	res := runCheck(t, NewProber(testConfig()), Request{URL: "http://" + addr})

	if res.Up {
		t.Fatal("Up = true for a closed port")
	}
	if res.Kind != KindConnectionRefused {
		t.Errorf("Kind = %s, want %s", res.Kind, KindConnectionRefused)
	}
}

func TestCheckTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	cfg := Config{Timeout: 150 * time.Millisecond}
	res := runCheck(t, NewProber(cfg), Request{URL: srv.URL})

	if res.Up {
		t.Fatal("Up = true for a check that timed out")
	}
	if res.Kind != KindTimeout {
		t.Errorf("Kind = %s, want %s", res.Kind, KindTimeout)
	}
}

func TestCheckInvalidRequests(t *testing.T) {
	tests := []struct {
		name string
		req  Request
	}{
		{name: "empty URL", req: Request{URL: ""}},
		{name: "unsupported scheme", req: Request{URL: "ftp://example.com"}},
		{name: "missing host", req: Request{URL: "https://"}},
		{name: "credentials", req: Request{URL: "https://user:pass@example.com"}},
		{name: "bad method", req: Request{URL: "https://example.com", Method: "TRACE"}},
		{name: "managed header", req: Request{URL: "https://example.com", Headers: map[string]string{"Host": "evil"}}},
		{name: "header injection", req: Request{URL: "https://example.com", Headers: map[string]string{"X-Test": "a\r\nb"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := runCheck(t, NewProber(testConfig()), tt.req)
			if res.Kind != KindInvalidRequest {
				t.Errorf("Kind = %s, want %s (error %q)", res.Kind, KindInvalidRequest, res.Error)
			}
			if res.Up {
				t.Error("Up = true for an invalid request")
			}
		})
	}
}

func TestParseStatusMatcher(t *testing.T) {
	tests := []struct {
		spec  string
		code  int
		match bool
	}{
		{"", 200, true},
		{"", 500, false},
		{"200", 200, true},
		{"200", 201, false},
		{"200,204", 204, true},
		{"200-299", 250, true},
		{"200-299", 300, false},
		{"2xx", 204, true},
		{"5xx", 503, true},
		{"5xx", 200, false},
	}

	for _, tt := range tests {
		matcher, err := ParseStatusMatcher(tt.spec)
		if err != nil {
			t.Fatalf("ParseStatusMatcher(%q): %v", tt.spec, err)
		}
		if got := matcher.Match(tt.code); got != tt.match {
			t.Errorf("ParseStatusMatcher(%q).Match(%d) = %v, want %v", tt.spec, tt.code, got, tt.match)
		}
	}
}

func TestParseStatusMatcherErrors(t *testing.T) {
	for _, spec := range []string{"abc", "99", "600", "300-200", "2xx,", "1xx-2xx", "x"} {
		if _, err := ParseStatusMatcher(spec); err == nil {
			t.Errorf("ParseStatusMatcher(%q) = nil error, want error", spec)
		}
	}
}

func TestNormalizeHeadersRejectsControlCharacters(t *testing.T) {
	_, err := normalizeHeaders(map[string]string{"X-Bad": "value\x00"})
	if err == nil {
		t.Fatal("normalizeHeaders accepted a control character")
	}
}

func TestRedirectLoop(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL, http.StatusFound)
	}))
	defer srv.Close()

	res := runCheck(t, NewProber(testConfig()), Request{URL: srv.URL})
	if res.Up {
		t.Fatal("Up = true for a redirect loop")
	}
	if res.Kind != KindRedirectLoop {
		t.Errorf("Kind = %s, want %s", res.Kind, KindRedirectLoop)
	}
}

func TestErrorsAreClassified(t *testing.T) {
	if got := KindDNSFailure.Label(); !strings.Contains(got, "DNS") {
		t.Errorf("label = %q, want it to mention DNS", got)
	}
}
