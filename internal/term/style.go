package term

// Style applies ANSI attributes to text. A nil or disabled Style is a no-op,
// so callers never need to branch on whether color is enabled.
type Style struct {
	enabled bool
}

// NewStyle returns a Style that emits ANSI codes when enabled is true.
func NewStyle(enabled bool) *Style { return &Style{enabled: enabled} }

// Enabled reports whether the style emits ANSI codes.
func (s *Style) Enabled() bool { return s != nil && s.enabled }

func (s *Style) wrap(code, text string) string {
	if !s.Enabled() {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s *Style) Red(text string) string    { return s.wrap("31", text) }
func (s *Style) Green(text string) string  { return s.wrap("32", text) }
func (s *Style) Yellow(text string) string { return s.wrap("33", text) }
func (s *Style) Cyan(text string) string   { return s.wrap("36", text) }
func (s *Style) Bold(text string) string   { return s.wrap("1", text) }
func (s *Style) Dim(text string) string    { return s.wrap("2", text) }
