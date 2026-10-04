package term

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestColorEnabled(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("TERM", "xterm-256color")

	buf := &bytes.Buffer{}
	if ColorEnabled(buf, "auto") {
		t.Error("auto mode should disable color for a non-terminal writer")
	}
	if !ColorEnabled(buf, "always") {
		t.Error("always mode should enable color")
	}
	if ColorEnabled(buf, "never") {
		t.Error("never mode should disable color")
	}

	t.Setenv("NO_COLOR", "1")
	if ColorEnabled(buf, "auto") {
		t.Error("NO_COLOR should disable color in auto mode")
	}

	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	if ColorEnabled(buf, "auto") {
		t.Error("TERM=dumb should disable color in auto mode")
	}
}

func TestSpinnerDisabledIsSilent(t *testing.T) {
	var buf bytes.Buffer
	spinner := NewSpinner(&buf, false, nil)
	spinner.Start("working")
	spinner.Stop()
	if buf.Len() != 0 {
		t.Errorf("disabled spinner wrote %q, want nothing", buf.String())
	}
}

func TestSpinnerWritesAndClears(t *testing.T) {
	var buf bytes.Buffer
	spinner := NewSpinner(&buf, true, []string{"*"})
	spinner.Start("working")
	time.Sleep(20 * time.Millisecond)
	spinner.Stop()

	out := buf.String()
	if !strings.Contains(out, "working") {
		t.Errorf("spinner output = %q, want it to contain the message", out)
	}
	if !strings.HasSuffix(out, "\x1b[K") {
		t.Errorf("spinner output = %q, want it to end with a line clear", out)
	}
}

func TestSymbolSetsAreComplete(t *testing.T) {
	for _, s := range []Symbols{UnicodeSymbols(), ASCIISymbols()} {
		if s.Up == "" || s.Down == "" || s.Warn == "" || s.Info == "" || s.Arrow == "" || s.Sep == "" || s.Micro == "" {
			t.Errorf("symbol set has an empty field: %+v", s)
		}
	}
	if len(SpinnerFrames(true)) == 0 || len(SpinnerFrames(false)) == 0 {
		t.Error("spinner frames are empty")
	}
}
