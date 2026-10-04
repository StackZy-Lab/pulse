package probe

import (
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Request describes what to check. Method, Headers and Body are optional; an
// empty Method means GET.
type Request struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    string
}

// managedHeaders are set by the HTTP client itself. Rejecting them early gives
// the user a clear error instead of a confusing transport failure.
var managedHeaders = map[string]struct{}{
	"Host":              {},
	"Content-Length":    {},
	"Connection":        {},
	"Keep-Alive":        {},
	"Proxy-Connection":  {},
	"Transfer-Encoding": {},
	"Upgrade":           {},
	"Trailer":           {},
	"Te":                {},
}

// normalize validates the request and returns an owned, canonical form of it.
func (r Request) normalize() (*url.URL, string, map[string]string, error) {
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	if method == "" {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodOptions, http.MethodDelete:
	default:
		return nil, "", nil, fmt.Errorf("unsupported HTTP method %q", method)
	}

	if !utf8.ValidString(r.Body) {
		return nil, "", nil, errors.New("request body is not valid UTF-8")
	}

	target, err := normalizeURL(r.URL)
	if err != nil {
		return nil, "", nil, err
	}

	headers, err := normalizeHeaders(r.Headers)
	if err != nil {
		return nil, "", nil, err
	}
	return target, method, headers, nil
}

// normalizeURL parses and validates a target URL. It is exported so callers
// can validate a URL before starting a check.
func normalizeURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("URL is empty")
	}

	target, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	target.Scheme = strings.ToLower(target.Scheme)
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q: use http or https", target.Scheme)
	}
	if target.Host == "" {
		return nil, errors.New("URL has no host")
	}
	if target.User != nil {
		return nil, errors.New("URLs with embedded credentials are not supported")
	}
	return target, nil
}

func normalizeHeaders(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}

	out := make(map[string]string, len(in))
	for name, value := range in {
		if name == "" || strings.TrimSpace(name) != name {
			return nil, fmt.Errorf("invalid header name %q", name)
		}
		if !validHeaderName(name) {
			return nil, fmt.Errorf("invalid header name %q", name)
		}

		canonical := textproto.CanonicalMIMEHeaderKey(name)
		if _, managed := managedHeaders[canonical]; managed {
			return nil, fmt.Errorf("header %q is managed by the HTTP client and cannot be set", canonical)
		}
		if !validHeaderValue(value) {
			return nil, fmt.Errorf("header %q contains a prohibited character", canonical)
		}
		out[canonical] = value
	}
	return out, nil
}

func validHeaderName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return name != ""
}

// validHeaderValue rejects control characters so a header value can never be
// used to smuggle a second header or a bare CRLF into the request.
func validHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < ' ' && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}
