package term

// Symbols holds the glyphs used in output so they can degrade to ASCII on
// terminals or locales that do not render Unicode.
type Symbols struct {
	Up    string // a passing check
	Down  string // a failing check
	Warn  string // a warning finding
	Info  string // an informational finding
	Arrow string // a redirect hop
	Sep   string // inline separator
	Micro string // microsecond unit
}

// UnicodeSymbols is the default, used when UTF-8 output is expected.
func UnicodeSymbols() Symbols {
	return Symbols{Up: "✔", Down: "✖", Warn: "⚠", Info: "•", Arrow: "↳", Sep: "·", Micro: "µs"}
}

// ASCIISymbols is the portable fallback.
func ASCIISymbols() Symbols {
	return Symbols{Up: "+", Down: "x", Warn: "!", Info: "-", Arrow: "->", Sep: "|", Micro: "us"}
}

// SpinnerFrames returns the animation frames that match the symbol set.
func SpinnerFrames(unicode bool) []string {
	if unicode {
		return []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	}
	return []string{"-", "\\", "|", "/"}
}
