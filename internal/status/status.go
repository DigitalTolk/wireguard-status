// Package status turns raw WireGuard data into an evaluated report and tracks
// how long each interface has been degraded. It is read-only: restarting links
// is left to an external watchdog driven by the health endpoints.
//
// Every interface seen since startup is remembered and expected to keep working
// — if a known interface later disappears from the collection (or collection
// fails), it is reported as down, so a vanished link still alerts.
package status

import (
	"log"
	"sort"
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
	State        string
	HandshakeAge time.Duration // since last handshake; 0 when never
}

func (p PeerReport) Healthy() bool { return p.State == StateUp }

// InterfaceReport is an evaluated interface.
type InterfaceReport struct {
	Name       string
	PublicKey  string
	ListenPort int
	Peers      []PeerReport

	// Present is false when a known interface is missing from the current
	// collection; such an interface is reported as down.
	Present bool
	// Degraded is true when any peer is down/never, or the interface is missing.
	Degraded  bool
	DownSince time.Time // zero unless the interface is currently degraded
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
	Degraded    bool // any peer down (or interface missing) across all interfaces
	Err         string
}

// ifaceState is per-interface bookkeeping that survives across ticks.
type ifaceState struct {
	downSince time.Time
	present   bool // seen in the most recent successful collection
}

// Monitor collects, evaluates and caches the latest report.
type Monitor struct {
	cfg  *config.Config
	coll wg.Collector

	mu     sync.Mutex
	known  map[string]*ifaceState // every interface seen since startup
	latest *Report
}

func NewMonitor(cfg *config.Config, coll wg.Collector) *Monitor {
	return &Monitor{
		cfg:   cfg,
		coll:  coll,
		known: map[string]*ifaceState{},
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

// Run drives the monitor until stop is closed. It performs an initial tick
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

func (m *Monitor) stateFor(name string) *ifaceState {
	st := m.known[name]
	if st == nil {
		st = &ifaceState{}
		m.known[name] = st
	}
	return st
}

// missingReport marks a known interface as absent and returns a down report for
// it. Caller holds m.mu.
func (m *Monitor) missingReport(name string, now time.Time) InterfaceReport {
	st := m.stateFor(name)
	st.present = false
	if st.downSince.IsZero() {
		st.downSince = now
	}
	return InterfaceReport{Name: name, Degraded: true, DownSince: st.downSince}
}

// tick collects, evaluates, updates state, caches and returns the report.
func (m *Monitor) tick() *Report {
	now := time.Now()
	ifaces, err := m.coll.Collect()

	rep := &Report{GeneratedAt: now}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		// The collection itself failed: we can't verify anything, so every
		// known interface is assumed down.
		rep.Err = err.Error()
		rep.Degraded = true
		for name := range m.known {
			rep.Interfaces = append(rep.Interfaces, m.missingReport(name, now))
		}
		sortReports(rep.Interfaces)
		m.latest = rep
		log.Printf("collect failed: %v", err)
		return rep
	}

	stale := m.cfg.Thresholds.HandshakeStale.D()
	present := make(map[string]struct{}, len(ifaces))

	for _, iface := range ifaces {
		present[iface.Name] = struct{}{}
		st := m.stateFor(iface.Name)
		if !st.present {
			st.downSince = time.Time{} // reappeared (or first seen): fresh timer
		}
		st.present = true

		ir := InterfaceReport{
			Name:       iface.Name,
			PublicKey:  iface.PublicKey,
			ListenPort: iface.ListenPort,
			Present:    true,
		}
		for _, p := range iface.Peers {
			pr := PeerReport{Peer: p}
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

		if ir.Degraded {
			if st.downSince.IsZero() {
				st.downSince = now
			}
		} else {
			st.downSince = time.Time{}
		}
		ir.DownSince = st.downSince

		if ir.Degraded {
			rep.Degraded = true
		}
		rep.Interfaces = append(rep.Interfaces, ir)
	}

	// Known interfaces missing from this collection are treated as down.
	for name := range m.known {
		if _, ok := present[name]; ok {
			continue
		}
		rep.Interfaces = append(rep.Interfaces, m.missingReport(name, now))
		rep.Degraded = true
	}

	sortReports(rep.Interfaces)
	m.latest = rep
	return rep
}

// sortReports orders interfaces by name so the report is stable across ticks.
func sortReports(rs []InterfaceReport) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Name < rs[j].Name })
}
