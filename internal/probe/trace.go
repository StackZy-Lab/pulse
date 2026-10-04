package probe

import (
	"crypto/tls"
	"net/http/httptrace"
	"sync"
	"time"
)

// traceCollector accumulates httptrace events into per-phase timings. The
// callbacks fire from several goroutines (resolver, dialer, handshake), so
// every field is guarded by the mutex; tests should run with -race.
type traceCollector struct {
	mu sync.Mutex

	dnsStart     time.Time
	connectStart time.Time
	tlsStart     time.Time
	wroteAt      time.Time

	dns     time.Duration
	connect time.Duration
	tlsHS   time.Duration
	server  time.Duration

	remoteAddr string
}

func newTrace() *traceCollector { return &traceCollector{} }

func (t *traceCollector) hooks() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { t.mark(&t.dnsStart) },
		DNSDone:  func(httptrace.DNSDoneInfo) { t.accumulate(&t.dnsStart, &t.dns) },

		ConnectStart: func(_, _ string) { t.mark(&t.connectStart) },
		ConnectDone:  func(_, _ string, _ error) { t.accumulate(&t.connectStart, &t.connect) },

		TLSHandshakeStart: func() { t.mark(&t.tlsStart) },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { t.accumulate(&t.tlsStart, &t.tlsHS) },

		GotConn: func(info httptrace.GotConnInfo) {
			t.mu.Lock()
			defer t.mu.Unlock()
			if info.Conn != nil {
				t.remoteAddr = info.Conn.RemoteAddr().String()
			}
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { t.set(&t.wroteAt) },
		GotFirstResponseByte: func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			if !t.wroteAt.IsZero() {
				t.server += time.Since(t.wroteAt)
				t.wroteAt = time.Time{}
			}
		},
	}
}

// mark records a phase start, ignoring a second start while one is open. Dual
// stack dialing can open two connects at once; the measured pair is
// first-start to first-done, which is the one that matters for latency.
func (t *traceCollector) mark(field *time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if field.IsZero() {
		*field = time.Now()
	}
}

func (t *traceCollector) set(field *time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	*field = time.Now()
}

// accumulate closes an open phase and adds its duration to the running total,
// so a redirect chain reports the sum across hops rather than the last hop.
func (t *traceCollector) accumulate(start *time.Time, total *time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if start.IsZero() {
		return
	}
	*total += time.Since(*start)
	*start = time.Time{}
}

func (t *traceCollector) addr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remoteAddr
}

func (t *traceCollector) timing(started, ended time.Time) Timing {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Timing{
		DNS:     t.dns,
		Connect: t.connect,
		TLS:     t.tlsHS,
		Server:  t.server,
		Total:   ended.Sub(started),
	}
}

// lastPhase returns the phase that was still open when the check ended, so a
// timeout can be attributed to DNS, connecting, TLS or the server rather than
// reported as one opaque "timeout". At most one field is non-zero at a time,
// because accumulate clears a start when it closes the phase.
func (t *traceCollector) lastPhase() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch {
	case !t.dnsStart.IsZero():
		return "dns"
	case !t.connectStart.IsZero():
		return "dial"
	case !t.tlsStart.IsZero():
		return "tls"
	case !t.wroteAt.IsZero():
		return "header"
	default:
		return "unknown"
	}
}
