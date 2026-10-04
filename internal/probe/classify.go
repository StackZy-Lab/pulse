package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"syscall"
)

// classify maps a transport error onto a stable ErrorKind and a human-readable
// message. Order matters: context and redirect errors are checked before the
// generic net.Error timeout test, which would otherwise swallow them.
func classify(err error, trace *traceCollector) (ErrorKind, string) {
	if err == nil {
		return KindOK, ""
	}

	// http.Client wraps transport errors in *url.Error, which repeats the URL;
	// the inner error is the useful part.
	msg := err.Error()
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		msg = urlErr.Err.Error()
	}

	switch {
	case errors.Is(err, context.Canceled):
		return KindCanceled, "check canceled"
	case errors.Is(err, errRedirectLoop):
		return KindRedirectLoop, errRedirectLoop.Error()
	case errors.Is(err, errTooManyRedirects):
		return KindTooManyRedirects, errTooManyRedirects.Error()
	case errors.Is(err, errUnsafeRedirect):
		return KindUnsafeRedirect, errUnsafeRedirect.Error()
	case errors.Is(err, errCrossOriginBody):
		return KindUnsafeRedirect, errCrossOriginBody.Error()
	case errors.Is(err, context.DeadlineExceeded):
		phase := "unknown"
		if trace != nil {
			phase = trace.lastPhase()
		}
		return KindTimeout, describeTimeout(phase)
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return KindDNSFailure, msg
	}

	var invalidCert x509.CertificateInvalidError
	if errors.As(err, &invalidCert) {
		if invalidCert.Reason == x509.Expired {
			return KindTLSExpired, msg
		}
		return KindTLSError, msg
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return KindTLSError, msg
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return KindTLSError, msg
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return KindTLSError, msg
	}
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return KindTLSError, msg
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return KindConnectionRefused, msg
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return KindConnectionTimeout, msg
	}

	return KindNetworkError, msg
}

func describeTimeout(phase string) string {
	switch phase {
	case "dns":
		return "the DNS lookup did not finish before the timeout"
	case "dial":
		return "the TCP connection did not finish before the timeout"
	case "tls":
		return "the TLS handshake did not finish before the timeout"
	case "header":
		return "the server did not send response headers before the timeout"
	default:
		return "the check did not finish before the timeout"
	}
}
