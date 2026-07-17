// Package status turns raw WireGuard data into an evaluated report and tracks
// how long each interface has been degraded. It is read-only: restarting links
// is left to an external watchdog driven by the health endpoints.
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

	// Degraded is true when any peer is down/never. Drives alerting (health 503).
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
	Degraded    bool // any peer down across all interfaces
	Err         string
}

// Monitor collects, evaluates and caches the latest report.
type Monitor struct {
	cfg  *config.Config
	coll wg.Collector

	mu        sync.Mutex
	downSince map[string]time.Time // iface -> when it became degraded
	latest    *Report
}

func NewMonitor(cfg *config.Config, coll wg.Collector) *Monitor {
	return &Monitor{
		cfg:       cfg,
		coll:      coll,
		downSince: map[string]time.Time{},
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

// tick collects, evaluates, updates down-since tracking, caches and returns the
// report.
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
			Name:       iface.Name,
			PublicKey:  iface.PublicKey,
			ListenPort: iface.ListenPort,
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
			if m.downSince[iface.Name].IsZero() {
				m.downSince[iface.Name] = now
			}
		} else {
			delete(m.downSince, iface.Name)
		}
		ir.DownSince = m.downSince[iface.Name]

		if ir.Degraded {
			rep.Degraded = true
		}
		rep.Interfaces = append(rep.Interfaces, ir)
	}

	m.latest = rep
	return rep
}
