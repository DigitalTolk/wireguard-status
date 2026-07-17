package web

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DigitalTolk/wireguard-status/internal/auth"
	"github.com/DigitalTolk/wireguard-status/internal/config"
	"github.com/DigitalTolk/wireguard-status/internal/status"
	"github.com/DigitalTolk/wireguard-status/internal/wg"
)

type peerState int

const (
	healthy peerState = iota
	downState
)

// genColl returns a single interface whose one peer is fresh or stale,
// recomputed at each Collect so age comparisons stay correct.
type genColl struct{ state peerState }

func (g genColl) Collect() ([]wg.Interface, error) {
	p := wg.Peer{Interface: "wg0", PublicKey: "PeerKeyAAAAAAAAAAAAAAAA", AllowedIPs: []string{"10.0.0.0/24"}}
	switch g.state {
	case healthy:
		p.LastHandshake = time.Now()
	case downState:
		p.LastHandshake = time.Now().Add(-time.Hour)
	}
	return []wg.Interface{{Name: "wg0", ListenPort: 51820, Peers: []wg.Peer{p}}}, nil
}

type stubRst struct{ err error }

func (s stubRst) Restart(string) error { return s.err }

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	c := config.Defaults()
	c.Collector = "fake"
	c.Auth.Username = "admin"
	h, err := auth.Hash("pw")
	if err != nil {
		t.Fatal(err)
	}
	c.Auth.PasswordHash = h
	c.Auth.Password = ""
	return c
}

func serverWith(t *testing.T, state peerState) (*Server, *status.Monitor) {
	t.Helper()
	cfg := testConfig(t)
	mon := status.NewMonitor(cfg, genColl{state}, stubRst{})
	return NewServer(cfg, mon), mon
}

func TestBasicAuth(t *testing.T) {
	srv, _ := serverWith(t, healthy)
	h := srv.Handler() // one instance so the success cache persists across requests

	do := func(setup func(*http.Request)) int {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		setup(req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// No Authorization header -> denied.
	if code := do(func(*http.Request) {}); code != http.StatusUnauthorized {
		t.Errorf("no-auth: got %d, want 401", code)
	}
	// Valid credentials -> allowed, populates the success cache.
	if code := do(func(r *http.Request) { r.SetBasicAuth("admin", "pw") }); code != http.StatusOK {
		t.Errorf("valid: got %d, want 200", code)
	}
	// Same header again -> served from the cache.
	if code := do(func(r *http.Request) { r.SetBasicAuth("admin", "pw") }); code != http.StatusOK {
		t.Errorf("cached: got %d, want 200", code)
	}
	// Different header, wrong user -> cache miss then denied.
	if code := do(func(r *http.Request) { r.SetBasicAuth("nobody", "pw") }); code != http.StatusUnauthorized {
		t.Errorf("wrong-user: got %d, want 401", code)
	}
	// Correct user, wrong password -> denied.
	if code := do(func(r *http.Request) { r.SetBasicAuth("admin", "nope") }); code != http.StatusUnauthorized {
		t.Errorf("wrong-pass: got %d, want 401", code)
	}
	// Malformed Authorization header -> denied.
	if code := do(func(r *http.Request) { r.Header.Set("Authorization", "Basic %%%not-base64") }); code != http.StatusUnauthorized {
		t.Errorf("malformed: got %d, want 401", code)
	}
}

func TestHandleIndex(t *testing.T) {
	// Healthy -> 200.
	srv, _ := serverWith(t, healthy)
	rec := httptest.NewRecorder()
	srv.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("healthy index: got %d, want 200", rec.Code)
	}

	// Degraded -> 503.
	dsrv, _ := serverWith(t, downState)
	rec = httptest.NewRecorder()
	dsrv.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("degraded index: got %d, want 503", rec.Code)
	}

	// Degraded but ?strict=0 -> 200.
	rec = httptest.NewRecorder()
	dsrv.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/?strict=0", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("strict=0 index: got %d, want 200", rec.Code)
	}
}

func TestHandleIndexTemplateError(t *testing.T) {
	cfg := testConfig(t)
	mon := status.NewMonitor(cfg, genColl{healthy}, stubRst{})
	// A template that references a field pageData does not have fails at execute
	// time, after the header is written — exercising the fallback branch.
	s := &Server{cfg: cfg, mon: mon, tpl: template.Must(template.New("index.html").Parse("{{.Bogus}}"))}
	rec := httptest.NewRecorder()
	s.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if body := rec.Body.String(); !contains(body, "template error") {
		t.Errorf("expected template error comment, got %q", body)
	}
}

func TestHandleHealthHealthy(t *testing.T) {
	srv, _ := serverWith(t, healthy)
	rec := httptest.NewRecorder()
	srv.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("healthy health: got %d, want 200", rec.Code)
	}
}

func TestHandleHealthDegraded(t *testing.T) {
	cfg := testConfig(t)
	cfg.PollInterval = config.Duration(time.Millisecond)
	cfg.AutoRestart.Enabled = false
	mon := status.NewMonitor(cfg, genColl{downState}, stubRst{})

	stop := make(chan struct{})
	go mon.Run(stop)
	defer close(stop)

	// Wait for a second tick so the interface has a non-zero down-for, which
	// drives the DownForSec branch.
	deadline := time.Now().Add(2 * time.Second)
	for {
		rep := mon.Latest()
		if len(rep.Interfaces) > 0 && rep.Interfaces[0].DownFor(rep.GeneratedAt) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never observed a non-zero down-for")
		}
		time.Sleep(2 * time.Millisecond)
	}

	srv := NewServer(cfg, mon)
	rec := httptest.NewRecorder()
	srv.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("degraded health: got %d, want 503", rec.Code)
	}
	if body := rec.Body.String(); !contains(body, "\"peers_down\":1") {
		t.Errorf("degraded health body missing peers_down: %s", body)
	}
}

func TestHandleRestart(t *testing.T) {
	// Missing interface -> 400 (call directly; the route never yields an empty
	// path value).
	srv, _ := serverWith(t, healthy)
	rec := httptest.NewRecorder()
	srv.handleRestart(rec, httptest.NewRequest(http.MethodPost, "/restart/", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing iface: got %d, want 400", rec.Code)
	}

	// Successful restart -> redirect.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/restart/wg0", nil)
	req.SetPathValue("iface", "wg0")
	srv.handleRestart(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("ok restart: got %d, want 303", rec.Code)
	}

	// Failing restart with JSON Accept -> 502 JSON.
	cfg := testConfig(t)
	fsrv := NewServer(cfg, status.NewMonitor(cfg, genColl{healthy}, stubRst{err: errTest}))
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/restart/wg0", nil)
	req.SetPathValue("iface", "wg0")
	req.Header.Set("Accept", "application/json")
	fsrv.handleRestart(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("failing json restart: got %d, want 502", rec.Code)
	}

	// Failing restart without JSON Accept -> still redirects.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/restart/wg0", nil)
	req.SetPathValue("iface", "wg0")
	fsrv.handleRestart(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("failing html restart: got %d, want 303", rec.Code)
	}
}

var errTest = &restartErr{}

type restartErr struct{}

func (*restartErr) Error() string { return "restart failed" }

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
