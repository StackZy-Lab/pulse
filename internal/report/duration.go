package report

import (
	"fmt"
	"time"
)

// FormatDuration renders a duration with a compact, human-friendly unit.
// micro is the microsecond symbol to use ("µs" or "us").
func FormatDuration(d time.Duration, micro string) string {
	switch {
	case d <= 0:
		return "0 " + micro
	case d < time.Millisecond:
		return fmt.Sprintf("%d %s", d.Microseconds(), micro)
	case d < time.Second:
		return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000)
	case d < time.Minute:
		return fmt.Sprintf("%.2f s", d.Seconds())
	default:
		return d.Round(time.Second).String()
	}
}
