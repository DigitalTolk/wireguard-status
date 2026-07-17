// Package app holds the wg-status command's runtime logic behind a testable
// Run function, so cmd/wg-status/main.go is a thin, unavoidably-untested shim
// (it only wires os.Exit and OS signals to Run).
package app

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/DigitalTolk/wireguard-status/internal/auth"
	"github.com/DigitalTolk/wireguard-status/internal/config"
	"github.com/DigitalTolk/wireguard-status/internal/status"
	"github.com/DigitalTolk/wireguard-status/internal/web"
	"github.com/DigitalTolk/wireguard-status/internal/wg"
)

// Build metadata, injected at release time via -ldflags by GoReleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// hashFn is a seam over auth.Hash so tests can exercise the hashing-failure
// path (auth.Hash only fails if the system RNG does).
var hashFn = auth.Hash

// versionString renders the GoReleaser-injected build metadata.
func versionString() string {
	return fmt.Sprintf("wg-status %s (commit %s, built %s)", version, commit, date)
}

// Run parses args, loads config and serves until ctx is cancelled. It returns a
// process exit code and never calls os.Exit, so it is fully testable. stdout is
// used for the -version/-hash-password output; stderr for diagnostics.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// `wg-status version` (subcommand) as well as `-version` (flag) below.
	if len(args) > 0 && args[0] == "version" {
		fmt.Fprintln(stdout, versionString())
		return 0
	}

	fs := flag.NewFlagSet("wg-status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", envOr("WG_CONFIG", "wg-status.conf"), "path to INI config file (optional)")
	hashPw := fs.Bool("hash-password", false, "read a password from stdin and print its hash for [Auth] PasswordHash, then exit")
	showVersion := fs.Bool("version", false, "print version information and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintln(stdout, versionString())
		return 0
	}

	if *hashPw {
		return hashPassword(stdin, stdout, stderr)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 1
	}
	log.Printf("config: %s", cfg)

	var coll wg.Collector
	switch cfg.Collector {
	case "fake":
		coll = wg.NewFakeCollector()
		log.Printf("using FAKE collector (bogus demo data)")
	default:
		coll = wg.WgCollector{}
	}

	mon := status.NewMonitor(cfg, coll)
	stop := make(chan struct{})
	go mon.Run(stop)
	defer close(stop)

	srv := web.NewServer(cfg, mon)
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	serve := httpSrv.ListenAndServe
	scheme := "http"
	if cfg.TLSCert != "" {
		serve = func() error { return httpSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey) }
		scheme = "https"
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Printf("listening on %s (%s)", cfg.Listen, scheme)
		if err := serve(); !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case err := <-serveErr:
		fmt.Fprintf(stderr, "serve: %v\n", err)
		return 1
	case <-ctx.Done():
	}

	log.Printf("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	return 0
}

// hashPassword reads a single line from stdin and prints its hash to stdout.
//
//	printf '%s' 'my-password' | wg-status -hash-password
func hashPassword(stdin io.Reader, stdout, stderr io.Writer) int {
	fmt.Fprint(stderr, "Enter password (input is read from stdin): ")
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintf(stderr, "read password: %v\n", err)
		return 1
	}
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" {
		fmt.Fprintln(stderr, "empty password")
		return 1
	}
	h, err := hashFn(pw)
	if err != nil {
		fmt.Fprintf(stderr, "hash: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, h)
	return 0
}

func envOr(key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

// getenv is a seam over os.Getenv so envOr's branches are testable without
// mutating the real process environment.
var getenv = os.Getenv
