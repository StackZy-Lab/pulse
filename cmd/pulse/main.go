// Command pulse checks the health of a URL and prints the result of every
// check: HTTP status, per-phase latency, TLS details and redirects.
//
//	pulse https://example.com
//	pulse -n 5 --json example.com
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/StackZy-Lab/pulse/internal/cli"
	"github.com/StackZy-Lab/pulse/internal/term"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(cli.Run(ctx, os.Args[1:], cli.IO{
		In:       os.Stdin,
		Out:      os.Stdout,
		Err:      os.Stderr,
		InIsTTY:  term.IsTerminal(os.Stdin),
		OutIsTTY: term.IsTerminal(os.Stdout),
		ErrIsTTY: term.IsTerminal(os.Stderr),
	}))
}
