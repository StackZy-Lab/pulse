package probe

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"
)

// tlsCapture records the negotiated TLS session and, when certificate
// verification is disabled, the verification error that would otherwise abort
// the handshake. This lets a check report certificate problems alongside the
// response instead of losing all diagnostic detail.
type tlsCapture struct {
	manualVerify bool

	mu        sync.Mutex
	state     *tls.ConnectionState
	verifyErr error
}

func newTLSCapture(manualVerify bool) *tlsCapture {
	return &tlsCapture{manualVerify: manualVerify}
}

// connection is wired to tls.Config.VerifyConnection. It always returns nil so
// the handshake completes and the check can continue; whether the certificate
// is trustworthy is reported, not enforced, here.
func (c *tlsCapture) connection(cs tls.ConnectionState) error {
	var err error
	if c.manualVerify {
		err = verifyState(cs)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	state := cs
	c.state = &state
	// Keep the first error seen so a bad certificate on an intermediate
	// redirect hop is not masked by a good one at the end.
	if c.verifyErr == nil {
		c.verifyErr = err
	}
	return nil
}

func verifyState(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("server presented no certificate")
	}
	opts := x509.VerifyOptions{
		DNSName:       cs.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, err := cs.PeerCertificates[0].Verify(opts)
	return err
}

func (c *tlsCapture) info() *TLSInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == nil {
		return nil
	}

	info := &TLSInfo{
		Version:     tlsVersionName(c.state.Version),
		CipherSuite: tls.CipherSuiteName(c.state.CipherSuite),
		ServerName:  c.state.ServerName,
		ChainLength: len(c.state.PeerCertificates),
		Verified:    c.verifyErr == nil,
	}
	if c.verifyErr != nil {
		info.Error = c.verifyErr.Error()
	}
	if len(c.state.PeerCertificates) > 0 {
		leaf := c.state.PeerCertificates[0]
		info.Subject = leaf.Subject.CommonName
		info.Issuer = leaf.Issuer.CommonName
		info.DNSNames = leaf.DNSNames
		info.NotBefore = leaf.NotBefore
		info.NotAfter = leaf.NotAfter
		info.DaysToExpiry = int(time.Until(leaf.NotAfter).Hours() / 24)
	}
	return info
}

func (c *tlsCapture) expired() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	var invalid x509.CertificateInvalidError
	return errors.As(c.verifyErr, &invalid) && invalid.Reason == x509.Expired
}

func (c *tlsCapture) nameMismatch() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	var hostErr x509.HostnameError
	return errors.As(c.verifyErr, &hostErr)
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

func isWeakTLSVersion(version string) bool {
	switch version {
	case "TLS 1.0", "TLS 1.1", "SSL 3.0":
		return true
	default:
		return false
	}
}

// applyTLS attaches certificate details to res and derives the TLS-related
// findings. It never changes whether a check is up: in insecure mode the user
// has explicitly opted out of verification, and in secure mode a bad
// certificate already failed the handshake and was classified as an error.
func (p *Prober) applyTLS(res *Result, capture *tlsCapture) {
	info := capture.info()
	if info == nil {
		return
	}
	res.TLS = info

	if p.cfg.Insecure {
		res.addFinding(Finding{
			Code:     FindingInsecureTLS,
			Severity: SeverityWarning,
			Message:  "TLS certificate verification was disabled",
		})
	}

	if info.Error != "" {
		res.addFinding(Finding{
			Code:     FindingTLSVerifyFailed,
			Severity: SeverityWarning,
			Message:  "certificate verification failed: " + info.Error,
		})
		if capture.nameMismatch() {
			res.addFinding(Finding{
				Code:     FindingCertNameMismatch,
				Severity: SeverityWarning,
				Message:  "certificate does not match " + info.ServerName,
			})
		}
	}

	if p.cfg.TLSExpiryWarnDays >= 0 && !info.NotAfter.IsZero() &&
		info.DaysToExpiry <= p.cfg.TLSExpiryWarnDays {
		res.addFinding(Finding{
			Code:     FindingTLSExpiringSoon,
			Severity: SeverityWarning,
			Message:  expiryMessage(info.DaysToExpiry),
		})
	}

	if isWeakTLSVersion(info.Version) {
		res.addFinding(Finding{
			Code:     FindingWeakTLSVersion,
			Severity: SeverityWarning,
			Message:  "weak TLS version negotiated: " + info.Version,
		})
	}
}

func expiryMessage(days int) string {
	switch {
	case days < 0:
		return fmt.Sprintf("certificate expired %d day(s) ago", -days)
	case days == 0:
		return "certificate expires today"
	case days == 1:
		return "certificate expires in 1 day"
	default:
		return fmt.Sprintf("certificate expires in %d days", days)
	}
}
