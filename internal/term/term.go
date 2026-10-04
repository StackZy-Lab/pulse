// Package term holds small terminal helpers: TTY detection, color decisions,
// symbol sets and an inline spinner. It has no dependencies beyond the standard
// library and degrades to plain text when the output is not a terminal.
package term

import (
	"io"
	"os"
	"strings"
)

// IsTerminal reports whether w is an interactive terminal.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// ColorEnabled decides whether ANSI color should be used for w. mode is
// "auto", "always" or "never". In auto mode the NO_COLOR convention and
// TERM=dumb are honored.
func ColorEnabled(w io.Writer, mode string) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	if os.Getenv("CLICOLOR_FORCE") != "" && os.Getenv("CLICOLOR_FORCE") != "0" {
		return true
	}
	return IsTerminal(w)
}

// UnicodeEnabled reports whether the locale suggests UTF-8 output. When no
// locale is set it defaults to true, since modern terminals handle UTF-8.
func UnicodeEnabled() bool {
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		value := strings.ToLower(os.Getenv(key))
		if value == "" {
			continue
		}
		return strings.Contains(value, "utf-8") || strings.Contains(value, "utf8")
	}
	return true
}
