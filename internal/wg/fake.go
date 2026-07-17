package wg

import (
	"fmt"
	"sync"
	"time"
)

// FakeCollector generates believable, lively bogus data so the whole app can
// be exercised locally without a kernel WireGuard interface. It also acts as
// its own Restarter: "restarting" an interface marks its flapping peer healthy
// again, so the manual button and the auto-restart loop are both observable.
//
// Behaviour:
//   - Healthy peers always report a fresh handshake and steadily-growing counters.
//   - Each "flapping" peer's handshake freezes at its last recovery time, so it
//     ages past the stale threshold ~45s after recovery and stays down until an
//     interface restart resets it. Combined with a short auto_restart.down_for in
//     the demo config this produces a visible up→down→restart→up cycle.
type FakeCollector struct {
	mu      sync.Mutex
	start   time.Time
	recover map[string]time.Time // iface -> last time its flapping peer recovered
}

func NewFakeCollector() *FakeCollector {
	now := time.Now()
	return &FakeCollector{
		start:   now,
		recover: map[string]time.Time{"wg-mesh": now},
	}
}

func (f *FakeCollector) Restart(iface string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.recover[iface]; !ok {
		return fmt.Errorf("unknown interface %q", iface)
	}
	f.recover[iface] = time.Now()
	return nil
}

func (f *FakeCollector) Collect() ([]Interface, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(f.start)

	// Healthy handshake: fresh, jittering a little to look alive.
	fresh := now.Add(-time.Duration(int(elapsed.Seconds())%18) * time.Second)
	// Steadily growing counters keyed off elapsed seconds.
	grow := func(base, rate uint64) uint64 { return base + uint64(elapsed.Seconds())*rate }

	flap := f.recover["wg-mesh"] // flapping peer's frozen handshake

	return []Interface{
		{
			Name: "wg0", PublicKey: "SrvWg0PubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0=", ListenPort: 51820,
			Peers: []Peer{
				{Interface: "wg0", PublicKey: "Office1PubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAA01=",
					Endpoint: "203.0.113.10:51820", AllowedIPs: []string{"10.10.0.2/32"},
					LastHandshake: fresh, RxBytes: grow(8_400_000, 2300), TxBytes: grow(3_100_000, 1700), PersistentKeepalive: 25},
			},
		},
		{
			Name: "wg2", PublicKey: "SrvWg2PubKeyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB2=", ListenPort: 51821,
			Peers: []Peer{
				{Interface: "wg2", PublicKey: "Office2PubKeyBBBBBBBBBBBBBBBBBBBBBBBBBBBB02=",
					Endpoint: "198.51.100.22:51820", AllowedIPs: []string{"10.20.0.2/32"},
					LastHandshake: fresh.Add(-3 * time.Second), RxBytes: grow(15_900_000, 4100), TxBytes: grow(6_700_000, 2600), PersistentKeepalive: 25},
			},
		},
		{
			Name: "wg-mesh", PublicKey: "MeshHubPubKeyCCCCCCCCCCCCCCCCCCCCCCCCCCCCC3=", ListenPort: 51830,
			Peers: []Peer{
				{Interface: "wg-mesh", PublicKey: "MeshVpcAPubKeyCCCCCCCCCCCCCCCCCCCCCCCCCC03=",
					Endpoint: "203.0.113.40:51830", AllowedIPs: []string{"10.40.0.0/16"},
					LastHandshake: fresh.Add(-9 * time.Second), RxBytes: grow(42_300_000, 5200), TxBytes: grow(38_100_000, 4900), PersistentKeepalive: 25},
				// The flapping peer: handshake frozen at last recovery.
				{Interface: "wg-mesh", PublicKey: "MeshVpcBPubKeyDDDDDDDDDDDDDDDDDDDDDDDDDD04=",
					Endpoint: "203.0.113.41:51830", AllowedIPs: []string{"10.41.0.0/16"},
					LastHandshake: flap, RxBytes: 27_500_000, TxBytes: 19_200_000, PersistentKeepalive: 25},
			},
		},
		{
			Name: "wg-mesh-stg", PublicKey: "MeshStgPubKeyEEEEEEEEEEEEEEEEEEEEEEEEEEEEE5=", ListenPort: 51831,
			Peers: []Peer{
				{Interface: "wg-mesh-stg", PublicKey: "StgRemotePubKeyEEEEEEEEEEEEEEEEEEEEEEEEE05=",
					Endpoint: "192.0.2.50:51831", AllowedIPs: []string{"10.50.0.0/16"},
					LastHandshake: fresh.Add(-12 * time.Second), RxBytes: grow(5_100_000, 900), TxBytes: grow(4_400_000, 800), PersistentKeepalive: 25},
			},
		},
	}, nil
}
