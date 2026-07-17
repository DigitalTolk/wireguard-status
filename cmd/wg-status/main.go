// Command wg-status serves a server-side-rendered WireGuard status page, a
// health endpoint that returns 503 while any monitored peer is down, and an
// auth-protected restart action. It auto-restarts persistently-down links.
//
// All logic lives in internal/app so it can be tested; main only wires OS
// signals and the process exit code to app.Run.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/DigitalTolk/wireguard-status/internal/app"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(app.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
