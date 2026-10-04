package probe

// ErrorKind is a stable, coarse classification of a check outcome. The values
// are part of the package's public API and are emitted verbatim by the JSON
// reporter, so treat them as a compatibility surface.
type ErrorKind string

const (
	KindOK                ErrorKind = "ok"
	KindInvalidRequest    ErrorKind = "invalid_request"
	KindDNSFailure        ErrorKind = "dns_failure"
	KindConnectionRefused ErrorKind = "connection_refused"
	KindConnectionTimeout ErrorKind = "connection_timeout"
	KindTLSError          ErrorKind = "tls_error"
	KindTLSExpired        ErrorKind = "tls_expired"
	KindTimeout           ErrorKind = "timeout"
	KindRedirectLoop      ErrorKind = "redirect_loop"
	KindTooManyRedirects  ErrorKind = "too_many_redirects"
	KindUnsafeRedirect    ErrorKind = "unsafe_redirect"
	KindStatusError       ErrorKind = "status_error"
	KindNetworkError      ErrorKind = "network_error"
	KindCanceled          ErrorKind = "canceled"
)

// Label returns a short, human-readable description of the kind, suitable for
// a one-line summary.
func (k ErrorKind) Label() string {
	switch k {
	case KindOK:
		return "ok"
	case KindInvalidRequest:
		return "invalid request"
	case KindDNSFailure:
		return "DNS failure"
	case KindConnectionRefused:
		return "connection refused"
	case KindConnectionTimeout:
		return "connection timeout"
	case KindTLSError:
		return "TLS error"
	case KindTLSExpired:
		return "TLS certificate expired"
	case KindTimeout:
		return "timeout"
	case KindRedirectLoop:
		return "redirect loop"
	case KindTooManyRedirects:
		return "too many redirects"
	case KindUnsafeRedirect:
		return "unsafe redirect"
	case KindStatusError:
		return "unexpected status"
	case KindNetworkError:
		return "network error"
	case KindCanceled:
		return "canceled"
	default:
		return string(k)
	}
}
