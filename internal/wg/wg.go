// Package wg models WireGuard interfaces/peers and provides collectors that
// produce them, plus restarters that bring links back up.
package wg

import "time"

// Interface is a WireGuard interface and its peers.
type Interface struct {
	Name       string
	PublicKey  string
	ListenPort int
	Peers      []Peer
}

// Peer is a single WireGuard peer as reported by the kernel netlink API.
type Peer struct {
	Interface           string
	PublicKey           string
	Endpoint            string
	AllowedIPs          []string
	LastHandshake       time.Time // zero value means "never"
	RxBytes             uint64
	TxBytes             uint64
	PersistentKeepalive int // seconds; 0 == off
}

// Collector returns the current set of WireGuard interfaces.
type Collector interface {
	Collect() ([]Interface, error)
}

// Restarter brings a (failing) interface back up.
type Restarter interface {
	Restart(iface string) error
}
