// Package web serves a static dashboard shell plus a JSON status API, all behind
// HTTP basic auth. The page renders itself client-side from GET /status, which
// also doubles as the health check (503 while degraded).
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

//go:embed favicon.svg
var faviconSVG []byte

// templates is parsed once at startup. The templates are embedded and known
// good, so a parse failure is a build-time programmer error, not a runtime
// condition — hence template.Must rather than a returned error.
var templates = template.Must(template.New("").ParseFS(templatesFS, "templates/*.html"))

// Server wires HTTP handlers to the monitor.
type Server struct {
	cfg *config.Config
	mon *status.Monitor
	tpl *template.Template
	dns *dnsResolver
}

func NewServer(cfg *config.Config, mon *status.Monitor) *Server {
	return &Server{cfg: cfg, mon: mon, tpl: templates, dns: newDNSResolver(24 * time.Hour)}
}

// Handler returns the fully-wired HTTP handler. robots.txt and the favicon are
// public; everything else is behind basic auth. Unknown paths get a 404 (the
// index only answers the exact root, GET /{$}).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public, unauthenticated.
	mux.HandleFunc("GET /robots.txt", handleRobots)
	mux.HandleFunc("GET /favicon.svg", handleFavicon)
	mux.HandleFunc("GET /favicon.ico", handleFavicon)

	// Auth-protected application routes. A dedicated mux means any path it does
	// not know answers 404 rather than falling through to the index.
	app := http.NewServeMux()
	app.HandleFunc("GET /{$}", s.handleIndex)
	app.HandleFunc("GET /status", s.handleStatus)
	app.HandleFunc("GET /status/{iface}", s.handleStatusIface)
	mux.Handle("/", s.basicAuth(app))

	return mux
}

func handleRobots(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "User-agent: *\nDisallow: /\n")
}

func handleFavicon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(faviconSVG)
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

// handleIndex serves the static dashboard shell. It always returns 200 — the
// page fetches GET /status and renders itself; health checks use /status.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The shell is tiny and changes on deploy — revalidate rather than cache.
	w.Header().Set("Cache-Control", "no-cache")
	_ = s.tpl.ExecuteTemplate(w, "index.html", nil)
}

// --- JSON status API --------------------------------------------------------

type peerJSON struct {
	PublicKey           string   `json:"public_key"`
	Endpoint            string   `json:"endpoint,omitempty"`
	EndpointDNS         string   `json:"endpoint_dns,omitempty"`
	AllowedIPs          []string `json:"allowed_ips,omitempty"`
	State               string   `json:"state"`
	LastHandshake       string   `json:"last_handshake,omitempty"` // RFC3339; omitted when never
	RxBytes             uint64   `json:"rx_bytes"`
	TxBytes             uint64   `json:"tx_bytes"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
}

type ifaceJSON struct {
	Name       string     `json:"name"`
	PublicKey  string     `json:"public_key"`
	ListenPort int        `json:"listen_port"`
	Present    bool       `json:"present"` // false when a known interface is missing
	Degraded   bool       `json:"degraded"`
	PeersTotal int        `json:"peers_total"`
	PeersDown  int        `json:"peers_down"`
	DownForSec int        `json:"down_for_seconds,omitempty"`
	Peers      []peerJSON `json:"peers"`
}

type statusJSON struct {
	Degraded          bool        `json:"degraded"`
	Error             string      `json:"error,omitempty"`
	PeersTotal        int         `json:"peers_total"`
	PeersDown         int         `json:"peers_down"`
	HandshakeStaleSec int         `json:"handshake_stale_seconds"`
	Interfaces        []ifaceJSON `json:"interfaces"`
	GeneratedAt       time.Time   `json:"generated_at"`
}

func (s *Server) buildIface(ir status.InterfaceReport, now time.Time) ifaceJSON {
	out := ifaceJSON{
		Name:       ir.Name,
		PublicKey:  ir.PublicKey,
		ListenPort: ir.ListenPort,
		Present:    ir.Present,
		Degraded:   ir.Degraded,
		PeersTotal: len(ir.Peers),
		Peers:      []peerJSON{},
	}
	if d := ir.DownFor(now); d > 0 {
		out.DownForSec = int(d.Seconds())
	}
	for _, p := range ir.Peers {
		if !p.Healthy() {
			out.PeersDown++
		}
		pj := peerJSON{
			PublicKey:           p.PublicKey,
			Endpoint:            p.Endpoint,
			EndpointDNS:         s.dns.name(p.Endpoint),
			AllowedIPs:          p.AllowedIPs,
			State:               p.State,
			RxBytes:             p.RxBytes,
			TxBytes:             p.TxBytes,
			PersistentKeepalive: p.PersistentKeepalive,
		}
		if !p.LastHandshake.IsZero() {
			pj.LastHandshake = p.LastHandshake.Format(time.RFC3339)
		}
		out.Peers = append(out.Peers, pj)
	}
	return out
}

func (s *Server) buildStatus(rep *status.Report) statusJSON {
	out := statusJSON{
		Degraded:          rep.Degraded,
		Error:             rep.Err,
		HandshakeStaleSec: int(s.cfg.Thresholds.HandshakeStale.D().Seconds()),
		Interfaces:        []ifaceJSON{},
		GeneratedAt:       rep.GeneratedAt,
	}
	for _, ir := range rep.Interfaces {
		ij := s.buildIface(ir, rep.GeneratedAt)
		out.PeersTotal += ij.PeersTotal
		out.PeersDown += ij.PeersDown
		out.Interfaces = append(out.Interfaces, ij)
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	// Live state that is polled — never serve it from a cache.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// degradedCode returns 503 when degraded, unless ?strict=0 forces 200 (for the
// page's own fetch); otherwise 200.
func degradedCode(r *http.Request, degraded bool) int {
	if degraded && r.URL.Query().Get("strict") != "0" {
		return http.StatusServiceUnavailable
	}
	return http.StatusOK
}

// handleStatus is the complete state of every interface, with overall totals.
// It is the health endpoint: 503 while any peer is down (or collection failed).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	rep := s.mon.Latest()
	writeJSON(w, degradedCode(r, rep.Degraded), s.buildStatus(rep))
}

// handleStatusIface is one interface (404 if unknown), so a watchdog can monitor
// and restart interfaces individually. 503 while that interface is degraded.
func (s *Server) handleStatusIface(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("iface")
	rep := s.mon.Latest()
	for _, ir := range rep.Interfaces {
		if ir.Name == name {
			writeJSON(w, degradedCode(r, ir.Degraded), s.buildIface(ir, rep.GeneratedAt))
			return
		}
	}
	http.Error(w, "unknown interface", http.StatusNotFound)
}
