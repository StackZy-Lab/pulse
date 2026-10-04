package probe

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

var (
	errRedirectLoop     = errors.New("redirect loop detected")
	errTooManyRedirects = errors.New("too many redirects")
	errUnsafeRedirect   = errors.New("redirected to an unsupported URL scheme")
	errCrossOriginBody  = errors.New("refusing to resend a request body to a different origin")
)

// redirectTracker enforces the redirect policy and records each hop. It is
// used only as http.Client.CheckRedirect, which is always called on the
// goroutine executing the request, so it needs no locking.
type redirectTracker struct {
	max         int
	origin      *url.URL
	headerNames []string
	hops        []Redirect
	seen        map[string]bool
	findings    []Finding
}

func newRedirectTracker(max int, origin *url.URL, headers map[string]string) *redirectTracker {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	return &redirectTracker{
		max:         max,
		origin:      origin,
		headerNames: names,
		seen:        map[string]bool{canonicalURL(origin): true},
	}
}

func (r *redirectTracker) check(req *http.Request, via []*http.Request) error {
	hop := Redirect{To: req.URL.String()}
	if len(via) > 0 {
		previous := via[len(via)-1]
		hop.From = previous.URL.String()

		// net/http copies the original request headers onto every redirect.
		// When the origin changes, strip the caller's headers (and the usual
		// credential headers) so they are never sent to a host the user did
		// not configure.
		if !sameOrigin(r.origin, req.URL) {
			for _, name := range r.headerNames {
				req.Header.Del(name)
			}
			req.Header.Del("Authorization")
			req.Header.Del("Cookie")
			req.Header.Del("Proxy-Authorization")
		}
		// A redirect that drops the body must not keep entity headers
		// describing it.
		if previous.Method != req.Method && req.Body == nil {
			for _, name := range []string{"Content-Encoding", "Content-Language", "Content-Location", "Content-Type", "Digest"} {
				req.Header.Del(name)
			}
		}
	}
	if req.Response != nil {
		hop.StatusCode = req.Response.StatusCode
	}
	r.hops = append(r.hops, hop)

	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return errUnsafeRedirect
	}
	if r.origin.Scheme == "https" && req.URL.Scheme == "http" {
		r.addFinding(Finding{
			Code:     FindingHTTPSDowngrade,
			Severity: SeverityWarning,
			Message:  "redirected from HTTPS to HTTP",
		})
	}
	if !strings.EqualFold(req.URL.Hostname(), r.origin.Hostname()) {
		r.addFinding(Finding{
			Code:     FindingHostChange,
			Severity: SeverityInfo,
			Message:  "redirected to a different host: " + req.URL.Hostname(),
		})
	}
	// A 307/308 preserves the body. Do not send a caller-provided payload to an
	// origin that was not the one configured.
	if !sameOrigin(r.origin, req.URL) && req.Body != nil {
		return errCrossOriginBody
	}

	key := canonicalURL(req.URL)
	if r.seen[key] {
		return errRedirectLoop
	}
	r.seen[key] = true

	if len(via) > r.max {
		return errTooManyRedirects
	}
	return nil
}

func (r *redirectTracker) addFinding(f Finding) {
	for _, existing := range r.findings {
		if existing.Code == f.Code {
			return
		}
	}
	r.findings = append(r.findings, f)
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func canonicalURL(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.EscapedPath() + "?" + u.RawQuery
}
