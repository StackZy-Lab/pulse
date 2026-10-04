// Package report renders probe results, either as a human-readable terminal
// report or as JSON. It owns all presentation concerns so the probe package can
// stay focused on performing checks.
package report

import (
	"time"

	"github.com/StackZy-Lab/pulse/internal/probe"
	"github.com/StackZy-Lab/pulse/internal/term"
)

// Report is the full set of results for one run.
type Report struct {
	URL     string
	Method  string
	Checks  int
	Timeout time.Duration
	Results []*probe.Result
}

// Options controls rendering.
type Options struct {
	Style   *term.Style
	Symbols term.Symbols
}

// Stats summarizes a run's durations.
type Stats struct {
	Checks int
	Up     int
	Down   int
	Avg    time.Duration
	Min    time.Duration
	Max    time.Duration
}

// Summarize computes Stats over the report's results.
func Summarize(results []*probe.Result) Stats {
	stats := Stats{Checks: len(results)}
	var total time.Duration
	for _, res := range results {
		if res.Up {
			stats.Up++
		} else {
			stats.Down++
		}
		if res.Duration <= 0 {
			continue
		}
		if stats.Min == 0 || res.Duration < stats.Min {
			stats.Min = res.Duration
		}
		if res.Duration > stats.Max {
			stats.Max = res.Duration
		}
		total += res.Duration
	}
	if stats.Checks > 0 {
		stats.Avg = total / time.Duration(stats.Checks)
	}
	return stats
}
