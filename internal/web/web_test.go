package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
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
	mixedState // one peer up, one down (degraded but not fully down)
)

// genColl returns a single interface, recomputing peer handshakes at each
// Collect so age comparisons stay correct.
type genColl struct{ state peerState }

func (g genColl) Collect() ([]wg.Interface, error) {
	mk := func(key, endpoint string, up bool) wg.Peer {
		p := wg.Peer{Interface: "wg0", PublicKey: key, Endpoint: endpoint, AllowedIPs: []string{"10.0.0.0/24"}, PersistentKeepalive: 25}
		if up {
			p.LastHandshake = time.Now()
		} else {
			p.LastHandshake = time.Now().Add(-time.Hour)
		}
		return p
	}
	var peers []wg.Peer
	switch g.state {
	case healthy:
		peers = []wg.Peer{mk("up1", "203.0.113.7:51820", true)}
	case downState:
		peers = []wg.Peer{mk("down1", "203.0.113.8:51820", false)}
	case mixedState:
		peers = []wg.Peer{mk("up1", "203.0.113.7:51820", true), mk("down1", "203.0.113.8:51820", false)}
	}
	return []wg.Interface{{
		Name:       "wg0",
		PublicKey:  "IfacePubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0=",
		ListenPort: 51820,
		Peers:      peers,
	}}, nil
}

type errColl struct{}

func (errColl) Collect() ([]wg.Interface, error) { return nil, errors.New("collect boom") }

// muxColl is a mutable collector so a test can make an interface vanish.
type muxColl struct {
	mu     sync.Mutex
	ifaces []wg.Interface
}

func (c *muxColl) set(ifaces []wg.Interface) { c.mu.Lock(); c.ifaces = ifaces; c.mu.Unlock() }
func (c *muxColl) Collect() ([]wg.Interface, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ifaces, nil
}

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

func serverWith(t *testing.T, coll wg.Collector) (*Server, *status.Monitor) {
	t.Helper()
	cfg := testConfig(t)
	mon := status.NewMonitor(cfg, coll)
	srv := NewServer(cfg, mon)
	// Keep tests hermetic: never touch the real resolver.
	srv.dns.lookup = func(string) ([]string, error) { return nil, nil }
	return srv, mon
}

func get(t *testing.T, srv *Server, method, path string, authed bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if authed {
		req.SetBasicAuth("admin", "pw")
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestBasicAuth(t *testing.T) {
	srv, _ := serverWith(t, genColl{healthy})
	h := srv.Handler() // one instance so the success cache persists across requests

	do := func(setup func(*http.Request)) int {
		req := httptest.NewRequest(http.MethodGet, "/status", nil)
		setup(req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do(func(*http.Request) {}); code != http.StatusUnauthorized {
		t.Errorf("no-auth: got %d, want 401", code)
	}
	if code := do(func(r *http.Request) { r.SetBasicAuth("admin", "pw") }); code != http.StatusOK {
		t.Errorf("valid: got %d, want 200", code)
	}
	if code := do(func(r *http.Request) { r.SetBasicAuth("admin", "pw") }); code != http.StatusOK {
		t.Errorf("cached: got %d, want 200", code)
	}
	if code := do(func(r *http.Request) { r.SetBasicAuth("nobody", "pw") }); code != http.StatusUnauthorized {
		t.Errorf("wrong-user: got %d, want 401", code)
	}
	if code := do(func(r *http.Request) { r.SetBasicAuth("admin", "nope") }); code != http.StatusUnauthorized {
		t.Errorf("wrong-pass: got %d, want 401", code)
	}
	if code := do(func(r *http.Request) { r.Header.Set("Authorization", "Basic %%%not-base64") }); code != http.StatusUnauthorized {
		t.Errorf("malformed: got %d, want 401", code)
	}
}

func TestRouting(t *testing.T) {
	srv, _ := serverWith(t, genColl{healthy})

	// robots.txt is public and disallows everything.
	if rec := get(t, srv, http.MethodGet, "/robots.txt", false); rec.Code != http.StatusOK ||
		!contains(rec.Body.String(), "Disallow: /") {
		t.Errorf("robots.txt: code=%d body=%q", rec.Code, rec.Body.String())
	}

	// The favicon is public SVG at both paths.
	for _, p := range []string{"/favicon.svg", "/favicon.ico"} {
		rec := get(t, srv, http.MethodGet, p, false)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/svg+xml" {
			t.Errorf("%s: code=%d ct=%q", p, rec.Code, rec.Header().Get("Content-Type"))
		}
	}

	// The shell and status render; an unknown path 404s (all authenticated).
	if rec := get(t, srv, http.MethodGet, "/", true); rec.Code != http.StatusOK {
		t.Errorf("root: got %d, want 200", rec.Code)
	}
	if rec := get(t, srv, http.MethodGet, "/status", true); rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", rec.Code)
	}
	if rec := get(t, srv, http.MethodGet, "/nope", true); rec.Code != http.StatusNotFound {
		t.Errorf("unknown path: got %d, want 404", rec.Code)
	}
}

func TestHandleIndexShell(t *testing.T) {
	srv, _ := serverWith(t, genColl{healthy})
	rec := httptest.NewRecorder()
	srv.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Errorf("shell: got %d, want 200", rec.Code)
	}
	// A static shell that renders itself from /status.
	if !contains(body, `id="app"`) || !contains(body, "fetch('/status") {
		t.Errorf("shell missing app/poll: %q", body)
	}
}

func TestHandleStatus(t *testing.T) {
	// Healthy -> 200 with totals.
	srv, _ := serverWith(t, genColl{healthy})
	rec := httptest.NewRecorder()
	srv.handleStatus(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("healthy status: got %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !contains(body, `"degraded":false`) || !contains(body, `"peers_total":1`) {
		t.Errorf("healthy status body: %s", body)
	}

	// Degraded (mixed) -> 503 with totals.
	dsrv, _ := serverWith(t, genColl{mixedState})
	rec = httptest.NewRecorder()
	dsrv.handleStatus(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("degraded status: got %d, want 503", rec.Code)
	}
	if body := rec.Body.String(); !contains(body, `"peers_total":2`) || !contains(body, `"peers_down":1`) {
		t.Errorf("degraded status totals: %s", body)
	}

	// Degraded but ?strict=0 -> 200.
	rec = httptest.NewRecorder()
	dsrv.handleStatus(rec, httptest.NewRequest(http.MethodGet, "/status?strict=0", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("strict=0 status: got %d, want 200", rec.Code)
	}
}

func TestHandleStatusCollectorError(t *testing.T) {
	srv, _ := serverWith(t, errColl{})
	rec := httptest.NewRecorder()
	srv.handleStatus(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("collector error: got %d, want 503", rec.Code)
	}
	if body := rec.Body.String(); !contains(body, `"error":"collect boom"`) || !contains(body, `"degraded":true`) {
		t.Errorf("collector error body: %s", body)
	}
}

func TestHandleStatusDownFor(t *testing.T) {
	cfg := testConfig(t)
	cfg.PollInterval = config.Duration(time.Millisecond)
	mon := status.NewMonitor(cfg, genColl{downState})

	stop := make(chan struct{})
	go mon.Run(stop)
	defer close(stop)

	// A second tick gives a non-zero down-for, exercising the DownFor branch.
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
	srv.dns.lookup = func(string) ([]string, error) { return nil, nil }
	rec := httptest.NewRecorder()
	srv.handleStatus(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("down status: got %d, want 503", rec.Code)
	}
}

func TestHandleStatusIface(t *testing.T) {
	srv, _ := serverWith(t, genColl{downState})

	// Known, degraded interface -> 503, a single object (no "interfaces" array).
	rec := get(t, srv, http.MethodGet, "/status/wg0", true)
	body := rec.Body.String()
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("iface status: got %d, want 503", rec.Code)
	}
	if !contains(body, `"name":"wg0"`) || !contains(body, `"peers":`) {
		t.Errorf("iface status body: %s", body)
	}
	if contains(body, `"interfaces"`) {
		t.Errorf("per-interface response must not wrap in interfaces: %s", body)
	}

	// ?strict=0 -> 200 even though degraded.
	if rec := get(t, srv, http.MethodGet, "/status/wg0?strict=0", true); rec.Code != http.StatusOK {
		t.Errorf("iface strict=0: got %d, want 200", rec.Code)
	}

	// Unknown interface -> 404.
	if rec := get(t, srv, http.MethodGet, "/status/ghost", true); rec.Code != http.StatusNotFound {
		t.Errorf("unknown iface: got %d, want 404", rec.Code)
	}
}

func TestHandleStatusMissingInterface(t *testing.T) {
	cfg := testConfig(t)
	cfg.PollInterval = config.Duration(time.Millisecond)
	c := &muxColl{}
	c.set([]wg.Interface{{Name: "wg0", PublicKey: "K", ListenPort: 51820,
		Peers: []wg.Peer{{PublicKey: "p", LastHandshake: time.Now()}}}})
	mon := status.NewMonitor(cfg, c)

	stop := make(chan struct{})
	go mon.Run(stop)
	defer close(stop)

	// Establish wg0 as known & healthy, then make it vanish.
	waitFor(t, func() bool {
		r := mon.Latest()
		return len(r.Interfaces) == 1 && r.Interfaces[0].Present
	})
	c.set(nil)
	waitFor(t, func() bool {
		r := mon.Latest()
		return len(r.Interfaces) == 1 && !r.Interfaces[0].Present
	})

	srv := NewServer(cfg, mon)
	srv.dns.lookup = func(string) ([]string, error) { return nil, nil }

	// The whole-fleet view marks it not present and degraded.
	rec := get(t, srv, http.MethodGet, "/status", true)
	if body := rec.Body.String(); !contains(body, `"present":false`) || !contains(body, `"degraded":true`) {
		t.Errorf("missing interface should be present:false degraded:true: %s", body)
	}
	// A watchdog on the missing interface sees 503.
	if rec := get(t, srv, http.MethodGet, "/status/wg0", true); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("missing iface /status/wg0: got %d, want 503", rec.Code)
	}
}

func TestHandleStatusIfaceHealthy(t *testing.T) {
	srv, _ := serverWith(t, genColl{healthy})
	if rec := get(t, srv, http.MethodGet, "/status/wg0", true); rec.Code != http.StatusOK {
		t.Errorf("healthy iface: got %d, want 200", rec.Code)
	}
}

func TestStatusReverseDNS(t *testing.T) {
	srv, _ := serverWith(t, genColl{healthy}) // healthy endpoint 203.0.113.7:51820
	srv.dns.lookup = func(string) ([]string, error) { return []string{"gw.example.com."}, nil }
	waitFor(t, func() bool { return srv.dns.name("203.0.113.7:51820") == "gw.example.com" })

	rec := httptest.NewRecorder()
	srv.handleStatus(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if !contains(rec.Body.String(), `"endpoint_dns":"gw.example.com"`) {
		t.Errorf("status should carry endpoint reverse-DNS: %s", rec.Body.String())
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
