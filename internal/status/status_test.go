package status

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/DigitalTolk/wireguard-status/internal/config"
	"github.com/DigitalTolk/wireguard-status/internal/wg"
)

// --- test doubles -----------------------------------------------------------

type errColl struct{}

func (errColl) Collect() ([]wg.Interface, error) { return nil, errors.New("collect boom") }

type fixedColl struct{ ifaces []wg.Interface }

func (f fixedColl) Collect() ([]wg.Interface, error) { return f.ifaces, nil }

// toggleColl returns a degraded or healthy interface depending on a mutable
// flag, so a single monitor can transition between states across ticks.
type toggleColl struct {
	mu   sync.Mutex
	down bool
}

func (t *toggleColl) set(down bool) { t.mu.Lock(); t.down = down; t.mu.Unlock() }

func (t *toggleColl) Collect() ([]wg.Interface, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	hs := time.Now()
	if t.down {
		hs = time.Now().Add(-time.Hour)
	}
	return []wg.Interface{{Name: "wg0", Peers: []wg.Peer{{Interface: "wg0", PublicKey: "K", LastHandshake: hs}}}}, nil
}

func testCfg() *config.Config {
	c := config.Defaults()
	c.Thresholds.HandshakeStale = config.Duration(180 * time.Second)
	return c
}

func healthyIfaces() []wg.Interface {
	return []wg.Interface{{Name: "wg0", Peers: []wg.Peer{{Interface: "wg0", PublicKey: "K", LastHandshake: time.Now()}}}}
}

// --- small pure helpers -----------------------------------------------------

func TestHealthyAndDownFor(t *testing.T) {
	if !(PeerReport{State: StateUp}).Healthy() {
		t.Error("up peer should be healthy")
	}
	if (PeerReport{State: StateDown}).Healthy() {
		t.Error("down peer should not be healthy")
	}

	now := time.Now()
	if d := (InterfaceReport{}).DownFor(now); d != 0 {
		t.Errorf("DownFor with zero DownSince = %v, want 0", d)
	}
	ir := InterfaceReport{DownSince: now.Add(-30 * time.Second)}
	if d := ir.DownFor(now); d < 29*time.Second {
		t.Errorf("DownFor = %v, want ~30s", d)
	}
}

// --- monitor behaviour ------------------------------------------------------

func TestLatestComputesThenCaches(t *testing.T) {
	m := NewMonitor(testCfg(), fixedColl{healthyIfaces()})
	first := m.Latest() // latest == nil -> tick
	if first == nil {
		t.Fatal("Latest returned nil")
	}
	if second := m.Latest(); second != first {
		t.Error("second Latest should return the cached report")
	}
}

func TestTickCollectorError(t *testing.T) {
	m := NewMonitor(testCfg(), errColl{})
	rep := m.tick()
	if rep.Err == "" || !rep.Degraded {
		t.Errorf("collector error should set Err and Degraded: %+v", rep)
	}
}

func TestTickPeerStates(t *testing.T) {
	ifaces := []wg.Interface{{
		Name: "wg0",
		Peers: []wg.Peer{
			{PublicKey: "up", LastHandshake: time.Now()},
			{PublicKey: "down", LastHandshake: time.Now().Add(-time.Hour)},
			{PublicKey: "never"}, // zero handshake
		},
	}}
	m := NewMonitor(testCfg(), fixedColl{ifaces})

	rep := m.tick()
	if !rep.Degraded {
		t.Fatal("interface with down/never peers should be degraded")
	}
	got := map[string]string{}
	for _, p := range rep.Interfaces[0].Peers {
		got[p.PublicKey] = p.State
	}
	want := map[string]string{"up": StateUp, "down": StateDown, "never": StateNever}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("peer %q state = %q, want %q", k, got[k], v)
		}
	}
}

func TestTickHealthyNotDegraded(t *testing.T) {
	m := NewMonitor(testCfg(), fixedColl{healthyIfaces()})
	rep := m.tick()
	if rep.Degraded {
		t.Error("an all-up interface should not be degraded")
	}
	if !rep.Interfaces[0].DownSince.IsZero() {
		t.Error("a healthy interface should have zero DownSince")
	}
}

func TestTickDownSincePersistsThenResets(t *testing.T) {
	coll := &toggleColl{down: true}
	m := NewMonitor(testCfg(), coll)

	m.tick()
	first := m.downSince["wg0"]
	if first.IsZero() {
		t.Fatal("downSince should be set while degraded")
	}
	m.tick() // still degraded -> downSince unchanged (else branch)
	if !m.downSince["wg0"].Equal(first) {
		t.Error("downSince should persist across ticks while degraded")
	}

	coll.set(false)
	m.tick() // healthy -> cleared
	if _, ok := m.downSince["wg0"]; ok {
		t.Error("downSince should be cleared when the interface recovers")
	}
}

func TestRunLoop(t *testing.T) {
	cfg := testCfg()
	cfg.PollInterval = config.Duration(time.Millisecond)
	m := NewMonitor(cfg, fixedColl{healthyIfaces()})

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { m.Run(stop); close(done) }()

	// Give the ticker time to fire at least once (covers the <-t.C case).
	time.Sleep(20 * time.Millisecond)
	if m.Latest() == nil {
		t.Error("Run should have produced a report")
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after stop")
	}
}
