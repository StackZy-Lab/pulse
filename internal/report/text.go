package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/StackZy-Lab/pulse/internal/probe"
	"github.com/StackZy-Lab/pulse/internal/term"
)

const (
	reasonWidth = 24
	durWidth    = 10
)

// Header prints the run banner: the target and the parameters in effect.
func Header(w io.Writer, rep Report, opts Options) {
	style := styleOf(opts)
	symbols := symbolsOf(opts)
	sep := " " + symbols.Sep + " "

	fmt.Fprintf(w, "%s%s%s\n", style.Cyan("pulse"), sep, rep.URL)

	parts := []string{rep.Method, plural(rep.Checks, "check"), "timeout " + rep.Timeout.String()}
	fmt.Fprintf(w, "%s\n\n", style.Dim(strings.Join(parts, sep)))
}

// Text prints a complete report in one call. Streaming callers can use Header,
// Check and Summary individually.
func Text(w io.Writer, rep Report, opts Options) {
	Header(w, rep, opts)
	for i, res := range rep.Results {
		Check(w, i+1, rep.Checks, res, opts)
	}
	Summary(w, rep, opts)
}

// Check prints one check block. It is designed to be called as each check
// finishes, so results appear as they complete.
func Check(w io.Writer, index, total int, res *probe.Result, opts Options) {
	style := styleOf(opts)
	symbols := symbolsOf(opts)
	numWidth := len(fmt.Sprintf("#%d", total))
	indent := strings.Repeat(" ", numWidth+4)

	status := style.Green(symbols.Up) + " " + style.Green(padRight("up", 4))
	reason := padRight(summaryLabel(res), reasonWidth)
	if !res.Up {
		status = style.Red(symbols.Down) + " " + style.Red(padRight("down", 4))
		reason = style.Red(reason)
	}

	fmt.Fprintf(w, "  %s  %s  %s  %s\n",
		padRight(fmt.Sprintf("#%d", index), numWidth),
		status,
		reason,
		padLeft(FormatDuration(res.Duration, symbols.Micro), durWidth),
	)

	if !res.Up && res.Error != "" {
		fmt.Fprintf(w, "%s%s\n", indent, style.Red(res.Error))
	}
	for _, line := range detailLines(res, style, symbols) {
		fmt.Fprintf(w, "%s%s\n", indent, line)
	}

	fmt.Fprintln(w)
}

// Summary prints the aggregate line for the run.
func Summary(w io.Writer, rep Report, opts Options) {
	style := styleOf(opts)
	symbols := symbolsOf(opts)
	sep := " " + symbols.Sep + " "
	stats := Summarize(rep.Results)

	up := style.Green(fmt.Sprintf("%d up", stats.Up))
	down := style.Dim(fmt.Sprintf("%d down", stats.Down))
	if stats.Down > 0 {
		down = style.Red(fmt.Sprintf("%d down", stats.Down))
	}

	parts := []string{up, down}
	if stats.Min > 0 {
		parts = append(parts,
			fmt.Sprintf("avg %s", FormatDuration(stats.Avg, symbols.Micro)),
			fmt.Sprintf("min %s", FormatDuration(stats.Min, symbols.Micro)),
			fmt.Sprintf("max %s", FormatDuration(stats.Max, symbols.Micro)),
		)
	}
	fmt.Fprintf(w, "  %s\n", strings.Join(parts, sep))
}

func detailLines(res *probe.Result, style *term.Style, symbols term.Symbols) []string {
	sep := " " + symbols.Sep + " "

	var lines []string

	// Phase breakdown: the reason this tool exists, so it is always shown.
	phases := []string{
		"dns " + FormatDuration(res.Timing.DNS, symbols.Micro),
		"connect " + FormatDuration(res.Timing.Connect, symbols.Micro),
	}
	if res.Timing.TLS > 0 {
		phases = append(phases, "tls "+FormatDuration(res.Timing.TLS, symbols.Micro))
	}
	if res.Timing.Server > 0 {
		phases = append(phases, "ttfb "+FormatDuration(res.Timing.Server, symbols.Micro))
	}
	lines = append(lines, style.Dim(strings.Join(phases, sep)))

	// Connection context: negotiated TLS and the address that answered.
	var context []string
	if res.TLS != nil {
		context = append(context, "tls "+res.TLS.Version)
		if !res.TLS.NotAfter.IsZero() {
			context = append(context, expiryPhrase(res.TLS.DaysToExpiry))
		}
	}
	if res.RemoteAddr != "" {
		context = append(context, res.RemoteAddr)
	}
	if len(context) > 0 {
		lines = append(lines, strings.Join(context, sep))
	}

	for _, hop := range res.Redirects {
		lines = append(lines, fmt.Sprintf("%s %d %s -> %s", symbols.Arrow, hop.StatusCode, hop.From, hop.To))
	}

	for _, finding := range res.Findings {
		if finding.Severity == probe.SeverityWarning {
			lines = append(lines, style.Yellow(fmt.Sprintf("%s %s", symbols.Warn, finding.Message)))
			continue
		}
		lines = append(lines, style.Dim(fmt.Sprintf("%s %s", symbols.Info, finding.Message)))
	}

	return lines
}

func summaryLabel(res *probe.Result) string {
	switch {
	case res.Up && res.StatusCode != 0:
		return res.StatusText()
	case res.Up:
		return "reachable"
	case res.Kind == probe.KindStatusError && res.StatusCode != 0:
		return res.StatusText()
	default:
		return res.Kind.Label()
	}
}

func expiryPhrase(days int) string {
	switch {
	case days < 0:
		return fmt.Sprintf("expired %d d ago", -days)
	case days == 0:
		return "expires today"
	case days == 1:
		return "expires in 1 d"
	default:
		return fmt.Sprintf("expires in %d d", days)
	}
}

func styleOf(opts Options) *term.Style {
	if opts.Style == nil {
		return term.NewStyle(false)
	}
	return opts.Style
}

// symbolsOf falls back to Unicode symbols when the caller did not set any, so
// the package is safe to use without explicit configuration.
func symbolsOf(opts Options) term.Symbols {
	if opts.Symbols.Up == "" {
		return term.UnicodeSymbols()
	}
	return opts.Symbols
}

func padRight(text string, width int) string {
	if len(text) >= width {
		return text
	}
	return text + strings.Repeat(" ", width-len(text))
}

func padLeft(text string, width int) string {
	if len(text) >= width {
		return text
	}
	return strings.Repeat(" ", width-len(text)) + text
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
