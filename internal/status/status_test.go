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

type recRst struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (r *recRst) Restart(string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return r.err
}

func (r *recRst) count() int { r.mu.Lock(); defer r.mu.Unlock(); return r.calls }

func testCfg() *config.Config {
	c := config.Defaults()
	c.Thresholds.HandshakeStale = config.Duration(180 * time.Second)
	return c
}

// --- small pure helpers -----------------------------------------------------

func TestShortKey(t *testing.T) {
	if got := shortKey("short"); got != "short" {
		t.Errorf("shortKey(short) = %q", got)
	}
	if got := shortKey("abcdefghijklmnop"); got != "abcdefgh…" {
		t.Errorf("shortKey(long) = %q", got)
	}
}

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

func healthyIfaces() []wg.Interface {
	return []wg.Interface{{Name: "wg0", Peers: []wg.Peer{{Interface: "wg0", PublicKey: "K", LastHandshake: time.Now()}}}}
}

func TestLatestComputesThenCaches(t *testing.T) {
	m := NewMonitor(testCfg(), fixedColl{healthyIfaces()}, &recRst{})
	first := m.Latest() // latest == nil -> tick
	if first == nil {
		t.Fatal("Latest returned nil")
	}
	if second := m.Latest(); second != first {
		t.Error("second Latest should return the cached report")
	}
}

func TestTickCollectorError(t *testing.T) {
	m := NewMonitor(testCfg(), errColl{}, &recRst{})
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
	cfg := testCfg()
	cfg.AutoRestart.Enabled = false
	m := NewMonitor(cfg, fixedColl{ifaces}, &recRst{})

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

func TestTickDownSincePersistsThenResets(t *testing.T) {
	cfg := testCfg()
	cfg.AutoRestart.Enabled = false
	coll := &toggleColl{down: true}
	m := NewMonitor(cfg, coll, &recRst{})

	m.tick()
	first := m.runtime["wg0"].downSince
	if first.IsZero() {
		t.Fatal("downSince should be set while degraded")
	}
	m.tick() // still degraded -> downSince unchanged (else branch)
	if !m.runtime["wg0"].downSince.Equal(first) {
		t.Error("downSince should persist across ticks while degraded")
	}

	coll.set(false)
	m.tick() // healthy -> runtime reset
	if !m.runtime["wg0"].downSince.IsZero() {
		t.Error("downSince should reset when the interface recovers")
	}
}

func TestTickTriggersAutoRestart(t *testing.T) {
	cfg := testCfg()
	cfg.AutoRestart.Enabled = true
	cfg.AutoRestart.DownFor = 0
	cfg.AutoRestart.Cooldown = 0
	cfg.AutoRestart.MaxAttempts = 3
	rst := &recRst{}
	m := NewMonitor(cfg, &toggleColl{down: true}, rst)

	m.tick()
	if rst.count() == 0 {
		t.Error("auto-restart should fire for a degraded interface")
	}
}

func TestManualRestart(t *testing.T) {
	// Success clears the error; the runtime entry is created on first use.
	okRst := &recRst{}
	m := NewMonitor(testCfg(), fixedColl{healthyIfaces()}, okRst)
	if err := m.Restart("wg0"); err != nil {
		t.Fatalf("manual restart: %v", err)
	}
	if m.runtime["wg0"].lastRestartErr != "" {
		t.Error("successful restart should clear lastRestartErr")
	}
	// A second restart re-uses the existing runtime entry.
	if err := m.Restart("wg0"); err != nil {
		t.Fatalf("second restart: %v", err)
	}

	// Failure records the error.
	badRst := &recRst{err: errors.New("nope")}
	fm := NewMonitor(testCfg(), fixedColl{healthyIfaces()}, badRst)
	if err := fm.Restart("wg0"); err == nil {
		t.Fatal("restart should surface the restarter error")
	}
	if fm.runtime["wg0"].lastRestartErr == "" {
		t.Error("failed restart should record lastRestartErr")
	}
}

func TestMaybeAutoRestart(t *testing.T) {
	base := func(down, cool time.Duration, max int) *config.Config {
		c := testCfg()
		c.AutoRestart.Enabled = true
		c.AutoRestart.DownFor = config.Duration(down)
		c.AutoRestart.Cooldown = config.Duration(cool)
		c.AutoRestart.MaxAttempts = max
		return c
	}
	now := time.Now()

	t.Run("too soon", func(t *testing.T) {
		rst := &recRst{}
		m := &Monitor{cfg: base(time.Minute, 0, 3), rst: rst, runtime: map[string]*ifaceRuntime{}}
		m.maybeAutoRestart("wg0", &ifaceRuntime{downSince: now}, now)
		if rst.count() != 0 {
			t.Error("should not restart before DownFor elapses")
		}
	})

	t.Run("cooldown", func(t *testing.T) {
		rst := &recRst{}
		m := &Monitor{cfg: base(0, time.Minute, 3), rst: rst, runtime: map[string]*ifaceRuntime{}}
		m.maybeAutoRestart("wg0", &ifaceRuntime{downSince: now.Add(-time.Hour), lastRestart: now}, now)
		if rst.count() != 0 {
			t.Error("should not restart during cooldown")
		}
	})

	t.Run("max attempts", func(t *testing.T) {
		rst := &recRst{}
		m := &Monitor{cfg: base(0, 0, 2), rst: rst, runtime: map[string]*ifaceRuntime{}}
		m.maybeAutoRestart("wg0", &ifaceRuntime{downSince: now.Add(-time.Hour), restartAttempts: 2}, now)
		if rst.count() != 0 {
			t.Error("should not restart past the attempt cap")
		}
	})

	t.Run("success", func(t *testing.T) {
		rst := &recRst{}
		m := &Monitor{cfg: base(0, 0, 3), rst: rst, runtime: map[string]*ifaceRuntime{}}
		rt := &ifaceRuntime{downSince: now.Add(-time.Hour), lastRestartErr: "old"}
		m.maybeAutoRestart("wg0", rt, now)
		if rst.count() != 1 || rt.lastRestartErr != "" || rt.restartAttempts != 1 {
			t.Errorf("expected one successful restart, rt=%+v calls=%d", rt, rst.count())
		}
	})

	t.Run("failure", func(t *testing.T) {
		rst := &recRst{err: errors.New("down")}
		m := &Monitor{cfg: base(0, 0, 3), rst: rst, runtime: map[string]*ifaceRuntime{}}
		rt := &ifaceRuntime{downSince: now.Add(-time.Hour)}
		m.maybeAutoRestart("wg0", rt, now)
		if rst.count() != 1 || rt.lastRestartErr == "" {
			t.Errorf("failed restart should record error, rt=%+v", rt)
		}
	})
}

func TestRunLoop(t *testing.T) {
	cfg := testCfg()
	cfg.PollInterval = config.Duration(time.Millisecond)
	cfg.AutoRestart.Enabled = false
	m := NewMonitor(cfg, fixedColl{healthyIfaces()}, &recRst{})

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
