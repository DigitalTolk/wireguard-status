// Package status turns raw WireGuard data into an evaluated report, tracks how
// long each interface has been degraded, and drives automatic restarts.
package status

import (
	"log"
	"sync"
	"time"

	"github.com/DigitalTolk/wireguard-status/internal/config"
	"github.com/DigitalTolk/wireguard-status/internal/wg"
)

// Peer states.
const (
	StateUp    = "up"
	StateDown  = "down"
	StateNever = "never" // never completed a handshake
)

// PeerReport is an evaluated peer.
type PeerReport struct {
	wg.Peer
	Name         string
	State        string
	HandshakeAge time.Duration // since last handshake; 0 when never
}

func (p PeerReport) Healthy() bool { return p.State == StateUp }

// shortKey is a compact display label for a peer's public key.
func shortKey(k string) string {
	if len(k) <= 11 {
		return k
	}
	return k[:8] + "…"
}

// InterfaceReport is an evaluated interface.
type InterfaceReport struct {
	Name        string
	PublicKey   string
	ListenPort  int
	Peers       []PeerReport
	AutoRestart bool

	// Degraded is true when any peer is down/never.
	Degraded        bool
	DownSince       time.Time // zero when not currently degraded
	LastRestart     time.Time
	LastRestartErr  string
	RestartAttempts int
}

// DownFor returns how long the interface has been degraded, or 0.
func (i InterfaceReport) DownFor(now time.Time) time.Duration {
	if i.DownSince.IsZero() {
		return 0
	}
	return now.Sub(i.DownSince)
}

// Report is the full evaluated snapshot.
type Report struct {
	GeneratedAt time.Time
	Interfaces  []InterfaceReport
	Degraded    bool // any peer down across all interfaces
	Err         string
}

// ifaceRuntime is the persisted-in-memory restart bookkeeping per interface.
type ifaceRuntime struct {
	downSince       time.Time
	lastRestart     time.Time
	lastRestartErr  string
	restartAttempts int
}

// Monitor collects, evaluates, caches the latest report, and runs auto-restart.
type Monitor struct {
	cfg  *config.Config
	coll wg.Collector
	rst  wg.Restarter

	mu      sync.Mutex
	runtime map[string]*ifaceRuntime
	latest  *Report
}

func NewMonitor(cfg *config.Config, coll wg.Collector, rst wg.Restarter) *Monitor {
	return &Monitor{
		cfg:     cfg,
		coll:    coll,
		rst:     rst,
		runtime: map[string]*ifaceRuntime{},
	}
}

// Latest returns the most recent evaluated report, computing one on demand if
// the background loop has not produced one yet.
func (m *Monitor) Latest() *Report {
	m.mu.Lock()
	r := m.latest
	m.mu.Unlock()
	if r != nil {
		return r
	}
	return m.tick()
}

// Run drives the monitor until ctx is done. It performs an initial tick
// immediately, then every poll interval.
func (m *Monitor) Run(stop <-chan struct{}) {
	m.tick()
	t := time.NewTicker(m.cfg.PollInterval.D())
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			m.tick()
		}
	}
}

// Restart triggers a manual restart of an interface and records the outcome.
func (m *Monitor) Restart(iface string) error {
	err := m.rst.Restart(iface)
	m.mu.Lock()
	rt := m.runtimeFor(iface)
	rt.lastRestart = time.Now()
	rt.restartAttempts++
	if err != nil {
		rt.lastRestartErr = err.Error()
	} else {
		rt.lastRestartErr = ""
	}
	m.mu.Unlock()
	if err != nil {
		log.Printf("manual restart of %s failed: %v", iface, err)
	} else {
		log.Printf("manual restart of %s ok", iface)
	}
	return err
}

func (m *Monitor) runtimeFor(iface string) *ifaceRuntime {
	rt := m.runtime[iface]
	if rt == nil {
		rt = &ifaceRuntime{}
		m.runtime[iface] = rt
	}
	return rt
}

// tick collects, evaluates, updates runtime state, applies auto-restart, caches
// and returns the report.
func (m *Monitor) tick() *Report {
	now := time.Now()
	ifaces, err := m.coll.Collect()

	rep := &Report{GeneratedAt: now}
	if err != nil {
		rep.Err = err.Error()
		rep.Degraded = true // collection failure is itself an alertable condition
		m.mu.Lock()
		m.latest = rep
		m.mu.Unlock()
		log.Printf("collect failed: %v", err)
		return rep
	}

	stale := m.cfg.Thresholds.HandshakeStale.D()

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, iface := range ifaces {
		ir := InterfaceReport{
			Name:        iface.Name,
			PublicKey:   iface.PublicKey,
			ListenPort:  iface.ListenPort,
			AutoRestart: m.cfg.AutoRestart.Enabled,
		}
		for _, p := range iface.Peers {
			pr := PeerReport{Peer: p, Name: shortKey(p.PublicKey)}
			switch {
			case p.LastHandshake.IsZero():
				pr.State = StateNever
			default:
				pr.HandshakeAge = now.Sub(p.LastHandshake)
				if pr.HandshakeAge > stale {
					pr.State = StateDown
				} else {
					pr.State = StateUp
				}
			}
			// Every peer is monitored: any non-up peer degrades the interface.
			if pr.State != StateUp {
				ir.Degraded = true
			}
			ir.Peers = append(ir.Peers, pr)
		}

		rt := m.runtimeFor(iface.Name)
		if ir.Degraded {
			if rt.downSince.IsZero() {
				rt.downSince = now
			}
		} else {
			rt.downSince = time.Time{}
			rt.restartAttempts = 0
			rt.lastRestartErr = ""
		}

		// Auto-restart decision.
		if ir.Degraded && ir.AutoRestart {
			m.maybeAutoRestart(iface.Name, rt, now)
		}

		ir.DownSince = rt.downSince
		ir.LastRestart = rt.lastRestart
		ir.LastRestartErr = rt.lastRestartErr
		ir.RestartAttempts = rt.restartAttempts

		if ir.Degraded {
			rep.Degraded = true
		}
		rep.Interfaces = append(rep.Interfaces, ir)
	}

	m.latest = rep
	return rep
}

// maybeAutoRestart attempts a restart if the interface has been down long
// enough, the cooldown has elapsed, and we are under the attempt cap. Caller
// holds m.mu.
func (m *Monitor) maybeAutoRestart(iface string, rt *ifaceRuntime, now time.Time) {
	ar := m.cfg.AutoRestart
	if now.Sub(rt.downSince) < ar.DownFor.D() {
		return
	}
	if !rt.lastRestart.IsZero() && now.Sub(rt.lastRestart) < ar.Cooldown.D() {
		return
	}
	if rt.restartAttempts >= ar.MaxAttempts {
		return
	}
	rt.lastRestart = now
	rt.restartAttempts++
	// Restart synchronously; commands are quick and this keeps state coherent.
	if err := m.rst.Restart(iface); err != nil {
		rt.lastRestartErr = err.Error()
		log.Printf("auto-restart of %s failed (attempt %d/%d): %v", iface, rt.restartAttempts, ar.MaxAttempts, err)
	} else {
		rt.lastRestartErr = ""
		log.Printf("auto-restart of %s ok (attempt %d/%d)", iface, rt.restartAttempts, ar.MaxAttempts)
	}
}
