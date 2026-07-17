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

// listColl is a mutable collector so a single monitor can watch interfaces
// appear, disappear and error across ticks.
type listColl struct {
	mu     sync.Mutex
	ifaces []wg.Interface
	err    error
}

func (l *listColl) set(ifaces []wg.Interface, err error) {
	l.mu.Lock()
	l.ifaces, l.err = ifaces, err
	l.mu.Unlock()
}

func (l *listColl) Collect() ([]wg.Interface, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ifaces, l.err
}

func testCfg() *config.Config {
	c := config.Defaults()
	c.Thresholds.HandshakeStale = config.Duration(180 * time.Second)
	return c
}

func healthyIfaces() []wg.Interface {
	return []wg.Interface{{Name: "wg0", Peers: []wg.Peer{{Interface: "wg0", PublicKey: "K", LastHandshake: time.Now()}}}}
}

func downIfaces() []wg.Interface {
	return []wg.Interface{{Name: "wg0", Peers: []wg.Peer{{Interface: "wg0", PublicKey: "d", LastHandshake: time.Now().Add(-time.Hour)}}}}
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
	if rep.Err == "" || !rep.Degraded || len(rep.Interfaces) != 0 {
		t.Errorf("first-tick collector error: %+v", rep)
	}
}

func TestTickCollectorErrorWithKnown(t *testing.T) {
	c := &listColl{}
	m := NewMonitor(testCfg(), c)
	c.set(healthyIfaces(), nil)
	m.tick() // wg0 now known & healthy

	c.set(nil, errors.New("netlink gone"))
	rep := m.tick()
	if rep.Err == "" || !rep.Degraded {
		t.Fatalf("collector error should set Err+Degraded: %+v", rep)
	}
	if len(rep.Interfaces) != 1 {
		t.Fatalf("known interface should still be reported: %+v", rep.Interfaces)
	}
	ir := rep.Interfaces[0]
	if ir.Name != "wg0" || ir.Present || !ir.Degraded {
		t.Errorf("known interface should be down on collector error: %+v", ir)
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
	if !rep.Interfaces[0].Present || !rep.Interfaces[0].DownSince.IsZero() {
		t.Errorf("healthy interface should be present with zero DownSince: %+v", rep.Interfaces[0])
	}
}

func TestTickDownSincePersists(t *testing.T) {
	m := NewMonitor(testCfg(), fixedColl{downIfaces()})
	m.tick()
	first := m.known["wg0"].downSince
	if first.IsZero() {
		t.Fatal("degraded interface should set downSince")
	}
	m.tick() // still degraded -> downSince unchanged
	if !m.known["wg0"].downSince.Equal(first) {
		t.Error("downSince should persist across consecutive degraded ticks")
	}
}

func TestTickMissingInterface(t *testing.T) {
	c := &listColl{}
	m := NewMonitor(testCfg(), c)

	c.set(healthyIfaces(), nil)
	if rep := m.tick(); rep.Degraded || !rep.Interfaces[0].Present {
		t.Fatalf("wg0 should be present & healthy: %+v", rep.Interfaces)
	}

	// Disappears -> reported down (missing).
	c.set(nil, nil)
	rep := m.tick()
	if !rep.Degraded || len(rep.Interfaces) != 1 {
		t.Fatalf("missing wg0 should be degraded: %+v", rep)
	}
	ir := rep.Interfaces[0]
	if ir.Name != "wg0" || ir.Present || !ir.Degraded || ir.DownSince.IsZero() {
		t.Errorf("missing wg0 report wrong: %+v", ir)
	}
	missingSince := ir.DownSince

	// Still missing -> downSince persists.
	if rep := m.tick(); !rep.Interfaces[0].DownSince.Equal(missingSince) {
		t.Error("missing interface downSince should persist")
	}

	// Reappears healthy -> present, down cleared.
	c.set(healthyIfaces(), nil)
	rep = m.tick()
	if rep.Degraded || !rep.Interfaces[0].Present || !rep.Interfaces[0].DownSince.IsZero() {
		t.Errorf("reappeared wg0 should be healthy with cleared down: %+v", rep.Interfaces[0])
	}
}

func TestTickReappearResetsTimer(t *testing.T) {
	c := &listColl{}
	m := NewMonitor(testCfg(), c)

	c.set(healthyIfaces(), nil)
	m.tick()
	c.set(nil, nil)
	m.tick() // missing since ~now
	missingSince := m.known["wg0"].downSince
	time.Sleep(5 * time.Millisecond)

	// Reappears still degraded -> the down timer resets to reappearance, not the
	// stale missing time.
	c.set(downIfaces(), nil)
	rep := m.tick()
	if ds := rep.Interfaces[0].DownSince; !ds.After(missingSince) {
		t.Errorf("reappearance should reset the down timer: was %v now %v", missingSince, ds)
	}
}

func TestTickSortsInterfaces(t *testing.T) {
	c := &listColl{}
	m := NewMonitor(testCfg(), c)
	c.set([]wg.Interface{
		{Name: "wg2", Peers: []wg.Peer{{PublicKey: "b", LastHandshake: time.Now()}}},
		{Name: "wg0", Peers: []wg.Peer{{PublicKey: "a", LastHandshake: time.Now()}}},
	}, nil)
	rep := m.tick()
	if len(rep.Interfaces) != 2 || rep.Interfaces[0].Name != "wg0" || rep.Interfaces[1].Name != "wg2" {
		t.Errorf("interfaces should be sorted by name: %+v", rep.Interfaces)
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
