// Package web renders the server-side status page and exposes the health and
// restart endpoints, all behind HTTP basic auth.
package web

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/DigitalTolk/wireguard-status/internal/auth"
	"github.com/DigitalTolk/wireguard-status/internal/config"
	"github.com/DigitalTolk/wireguard-status/internal/status"
)

//go:embed templates/*.html
var templatesFS embed.FS

// Server wires HTTP handlers to the monitor.
type Server struct {
	cfg *config.Config
	mon *status.Monitor
	tpl *template.Template
}

func NewServer(cfg *config.Config, mon *status.Monitor) (*Server, error) {
	tpl, err := template.New("").Funcs(tmplFuncs).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, mon: mon, tpl: tpl}, nil
}

// Handler returns the fully-wired, auth-protected HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /restart/{iface}", s.handleRestart)
	return s.basicAuth(mux)
}

func (s *Server) basicAuth(next http.Handler) http.Handler {
	wantU := []byte(s.cfg.Auth.Username)
	hash := s.cfg.Auth.PasswordHash

	// Verifying PBKDF2 on every request is expensive, so cache the last
	// Authorization header that verified successfully. Since the credential is
	// effectively constant, steady-state requests skip the KDF entirely.
	var (
		mu       sync.RWMutex
		lastGood string
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deny := func() {
			w.Header().Set("WWW-Authenticate", `Basic realm="wireguard-status"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
		hdr := r.Header.Get("Authorization")
		if hdr != "" {
			mu.RLock()
			cached := lastGood
			mu.RUnlock()
			if cached != "" && subtle.ConstantTimeCompare([]byte(hdr), []byte(cached)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}
		u, p, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(u), wantU) != 1 ||
			!auth.Verify(hash, p) {
			deny()
			return
		}
		mu.Lock()
		lastGood = hdr
		mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

type pageData struct {
	Report   *status.Report
	Stale    time.Duration
	Now      time.Time
	Refresh  int // seconds
	Degraded bool
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	rep := s.mon.Latest()

	// Honour the user's choice: the page itself returns 5xx when degraded so a
	// plain HTTP uptime check fires. ?strict=0 forces 200 for casual browsing.
	code := http.StatusOK
	if rep.Degraded && r.URL.Query().Get("strict") != "0" {
		code = http.StatusServiceUnavailable
	}

	data := pageData{
		Report:   rep,
		Stale:    s.cfg.Thresholds.HandshakeStale.D(),
		Now:      rep.GeneratedAt,
		Refresh:  5,
		Degraded: rep.Degraded,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	if err := s.tpl.ExecuteTemplate(w, "index.html", data); err != nil {
		// Headers already sent; nothing useful to do but log via http.Error fallback.
		fmt.Fprintf(w, "\n<!-- template error: %v -->", err)
	}
}

type healthIface struct {
	Name       string `json:"name"`
	Degraded   bool   `json:"degraded"`
	PeersTotal int    `json:"peers_total"`
	PeersDown  int    `json:"peers_down"`
	DownForSec int    `json:"down_for_seconds,omitempty"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	rep := s.mon.Latest()
	out := struct {
		Degraded   bool          `json:"degraded"`
		Error      string        `json:"error,omitempty"`
		Interfaces []healthIface `json:"interfaces"`
		Time       time.Time     `json:"time"`
	}{Degraded: rep.Degraded, Error: rep.Err, Time: rep.GeneratedAt}

	for _, ir := range rep.Interfaces {
		hi := healthIface{Name: ir.Name, Degraded: ir.Degraded, PeersTotal: len(ir.Peers)}
		for _, p := range ir.Peers {
			if !p.Healthy() {
				hi.PeersDown++
			}
		}
		if d := ir.DownFor(rep.GeneratedAt); d > 0 {
			hi.DownForSec = int(d.Seconds())
		}
		out.Interfaces = append(out.Interfaces, hi)
	}

	w.Header().Set("Content-Type", "application/json")
	if rep.Degraded {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	if iface == "" {
		http.Error(w, "missing interface", http.StatusBadRequest)
		return
	}
	err := s.mon.Restart(iface)
	if err != nil && r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{"interface": iface, "error": err.Error()})
		return
	}
	// Redirect back to the page so the SSR form post lands on a fresh render.
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
