package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"
)

// Prober performs HTTP(S) checks. It holds only configuration and is safe for
// concurrent use; every Check opens its own connection.
type Prober struct {
	cfg Config
}

// NewProber returns a Prober configured by cfg. Zero values are replaced by
// defaults; see Config.
func NewProber(cfg Config) *Prober {
	return &Prober{cfg: cfg.normalise()}
}

// Config returns a copy of the prober's effective configuration.
func (p *Prober) Config() Config { return p.cfg }

// Check performs one check and always returns a non-nil Result. A failed check
// is returned as data, never as an error.
//
// The supplied context bounds the check; if it has no deadline, Config.Timeout
// is applied on top of it.
func (p *Prober) Check(ctx context.Context, req Request) *Result {
	started := time.Now()
	res := &Result{URL: strings.TrimSpace(req.URL), StartedAt: started, Kind: KindOK}

	target, method, headers, err := req.normalize()
	if err != nil {
		res.Kind = KindInvalidRequest
		res.Error = err.Error()
		res.Duration = time.Since(started)
		return res
	}
	res.URL = target.String()
	res.Method = method

	trace := newTrace()
	capture := newTLSCapture(p.cfg.Insecure)
	tracker := newRedirectTracker(p.cfg.MaxRedirects, target, headers)

	transport := p.newTransport(capture, target.Hostname())
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport}
	if p.cfg.DisableRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		client.CheckRedirect = tracker.check
	}

	checkCtx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	checkCtx = httptrace.WithClientTrace(checkCtx, trace.hooks())

	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(checkCtx, method, target.String(), body)
	if err != nil {
		res.Kind = KindInvalidRequest
		res.Error = err.Error()
		res.Duration = time.Since(started)
		return res
	}
	for name, value := range headers {
		httpReq.Header.Set(name, value)
	}
	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", p.cfg.UserAgent)
	}
	if httpReq.Header.Get("Accept") == "" {
		httpReq.Header.Set("Accept", "*/*")
	}
	// Do not reuse this connection for another request.
	httpReq.Close = true

	resp, doErr := client.Do(httpReq)

	res.Redirects = tracker.hops
	for _, f := range tracker.findings {
		res.addFinding(f)
	}
	res.RemoteAddr = trace.addr()
	if resp != nil {
		defer resp.Body.Close()
		res.StatusCode = resp.StatusCode
		if resp.Request != nil {
			res.FinalURL = resp.Request.URL.String()
		}
	}

	if doErr != nil {
		res.Kind, res.Error = classify(doErr, trace)
		res.Timing = trace.timing(started, time.Now())
		res.Duration = time.Since(started)
		p.applyTLS(res, capture)
		return res
	}

	if p.cfg.MaxBodyBytes > 0 {
		n, _ := io.CopyN(io.Discard, resp.Body, p.cfg.MaxBodyBytes)
		res.BodySize = n
		res.BodyTruncated = n == p.cfg.MaxBodyBytes
	}

	res.Timing = trace.timing(started, time.Now())
	res.Duration = time.Since(started)
	p.applyTLS(res, capture)

	if res.Kind == KindOK && !p.cfg.ExpectStatus.Match(res.StatusCode) {
		res.Kind = KindStatusError
		res.Error = fmt.Sprintf("HTTP %s is not in the accepted status range (%s)",
			res.StatusText(), p.cfg.ExpectStatus.String())
	}
	res.Up = res.Kind == KindOK
	return res
}

func (p *Prober) newTransport(capture *tlsCapture, serverName string) *http.Transport {
	return &http.Transport{
		// Each check opens a fresh connection. Reusing one would skip DNS, the
		// TCP handshake and TLS negotiation, hiding exactly the problems this
		// tool exists to surface.
		DisableKeepAlives:     true,
		ExpectContinueTimeout: time.Second,
		DialContext:           (&net.Dialer{KeepAlive: -1}).DialContext,
		TLSClientConfig: &tls.Config{
			// InsecureSkipVerify is opt-in via Config.Insecure. When it is set,
			// tlsCapture performs the verification by hand so the result can
			// still report what was wrong with the certificate.
			InsecureSkipVerify: p.cfg.Insecure,
			ServerName:         serverName,
			MinVersion:         p.cfg.MinTLSVersion,
			VerifyConnection:   capture.connection,
		},
	}
}
