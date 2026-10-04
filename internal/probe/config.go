package probe

import (
	"crypto/tls"
	"time"
)

const (
	defaultTimeout           = 20 * time.Second
	defaultMaxRedirects      = 10
	defaultTLSExpiryWarnDays = 14
)

// Config tunes a Prober. Every field has a sensible default, so the zero value
// is usable: it performs GET checks over HTTPS with full certificate
// verification and follows up to ten redirects.
type Config struct {
	// Timeout bounds a single check, including redirects and the optional body
	// read. Defaults to 20s.
	Timeout time.Duration

	// DisableRedirects stops after the first 3xx response instead of following
	// it. Defaults to false (redirects are followed).
	DisableRedirects bool

	// MaxRedirects caps the number of redirects that are followed. Defaults to 10.
	MaxRedirects int

	// ExpectStatus decides which status codes count as success. The zero value
	// accepts 1xx-3xx.
	ExpectStatus StatusMatcher

	// Insecure disables TLS certificate verification. It is intended for
	// inspecting misconfigured servers; a finding is attached to every result.
	Insecure bool

	// MinTLSVersion is the minimum TLS version accepted. Defaults to TLS 1.2.
	MinTLSVersion uint16

	// MaxBodyBytes, when greater than zero, reads and discards up to that many
	// bytes of the response body so Result.BodySize is meaningful. When zero
	// (the default) the body is not read at all.
	MaxBodyBytes int64

	// UserAgent is sent when the request does not set one. Defaults to "pulse".
	UserAgent string

	// TLSExpiryWarnDays attaches a finding when the leaf certificate expires
	// within this many days. Defaults to 14; a negative value disables the check.
	TLSExpiryWarnDays int
}

func (c Config) normalise() Config {
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	if c.MaxRedirects <= 0 {
		c.MaxRedirects = defaultMaxRedirects
	}
	if c.MinTLSVersion == 0 {
		c.MinTLSVersion = tls.VersionTLS12
	}
	if c.UserAgent == "" {
		c.UserAgent = "pulse"
	}
	if c.TLSExpiryWarnDays == 0 {
		c.TLSExpiryWarnDays = defaultTLSExpiryWarnDays
	}
	return c
}
