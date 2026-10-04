package term

import (
	"fmt"
	"io"
	"sync"
	"time"
)

const spinnerInterval = 90 * time.Millisecond

// Spinner renders a single-line progress indicator for a long-running
// operation. When disabled it writes nothing, keeping redirected output clean.
type Spinner struct {
	w       io.Writer
	enabled bool
	frames  []string

	mu      sync.Mutex
	message string
	stop    chan struct{}
	done    chan struct{}
	running bool
}

// NewSpinner returns a spinner writing to w. Pass enabled=false to silence it.
func NewSpinner(w io.Writer, enabled bool, frames []string) *Spinner {
	if len(frames) == 0 {
		frames = []string{"-", "\\", "|", "/"}
	}
	return &Spinner{w: w, enabled: enabled, frames: frames}
}

// Start begins animating the given message. It is a no-op when the spinner is
// disabled or already running.
func (s *Spinner) Start(message string) {
	if !s.enabled {
		return
	}

	s.mu.Lock()
	if s.running {
		s.message = message
		s.mu.Unlock()
		return
	}
	s.running = true
	s.message = message
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	s.mu.Unlock()

	go s.loop()
}

func (s *Spinner) loop() {
	ticker := time.NewTicker(spinnerInterval)
	defer ticker.Stop()
	defer close(s.done)

	for i := 0; ; i++ {
		s.render(s.frames[i%len(s.frames)])
		select {
		case <-s.stop:
			return
		case <-ticker.C:
		}
	}
}

func (s *Spinner) render(frame string) {
	s.mu.Lock()
	message := s.message
	s.mu.Unlock()
	// \r returns to column 0 and \x1b[K clears the line before redrawing.
	fmt.Fprintf(s.w, "\r\x1b[K%s %s", frame, message)
}

// Stop halts the animation and clears the progress line. It is safe to call
// when the spinner was never started.
func (s *Spinner) Stop() {
	if !s.enabled {
		return
	}

	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	stop, done := s.stop, s.done
	s.running = false
	s.mu.Unlock()

	close(stop)
	<-done
	fmt.Fprint(s.w, "\r\x1b[K")
}
