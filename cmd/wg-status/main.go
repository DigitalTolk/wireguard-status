// Command wg-status serves a server-side-rendered WireGuard status page,
// a health endpoint that returns 503 while any monitored peer is down, and an
// auth-protected restart action. It auto-restarts persistently-down links.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DigitalTolk/wireguard-status/internal/auth"
	"github.com/DigitalTolk/wireguard-status/internal/config"
	"github.com/DigitalTolk/wireguard-status/internal/status"
	"github.com/DigitalTolk/wireguard-status/internal/web"
	"github.com/DigitalTolk/wireguard-status/internal/wg"
)

func main() {
	cfgPath := flag.String("config", envOr("WG_CONFIG", "wg-status.conf"), "path to INI config file (optional)")
	hashPw := flag.Bool("hash-password", false, "read a password from stdin and print its hash for [Auth] PasswordHash, then exit")
	flag.Parse()

	if *hashPw {
		hashPasswordAndExit()
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("config: %s", cfg)

	var (
		coll wg.Collector
		rst  wg.Restarter
	)
	switch cfg.Collector {
	case "fake":
		fc := wg.NewFakeCollector()
		coll, rst = fc, fc
		log.Printf("using FAKE collector (bogus demo data)")
	default:
		coll = wg.WgCollector{}
		rst = wg.CmdRestarter{Command: cfg.Restart.Command}
	}

	mon := status.NewMonitor(cfg, coll, rst)

	stop := make(chan struct{})
	go mon.Run(stop)

	srv, err := web.NewServer(cfg, mon)
	if err != nil {
		log.Fatalf("web: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		log.Printf("listening on %s", cfg.Listen)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down")
	close(stop)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

// hashPasswordAndExit reads a single line from stdin and prints its hash.
//
//	printf '%s' 'my-password' | wg-status -hash-password
func hashPasswordAndExit() {
	fmt.Fprint(os.Stderr, "Enter password (input is read from stdin): ")
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		log.Fatalf("read password: %v", err)
	}
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" {
		log.Fatal("empty password")
	}
	h, err := auth.Hash(pw)
	if err != nil {
		log.Fatalf("hash: %v", err)
	}
	fmt.Println(h)
	os.Exit(0)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
