package wg

import "time"

// FakeCollector generates believable, lively bogus data so the whole app can be
// exercised locally without a kernel WireGuard interface.
//
// Behaviour:
//   - Healthy peers always report a fresh handshake and steadily-growing counters.
//   - wg-mesh has one "flapping" peer whose handshake is frozen at startup, so it
//     ages past the stale threshold and shows as down — a degraded interface for
//     exercising the 503 / health-endpoint alerting.
type FakeCollector struct {
	start time.Time
}

func NewFakeCollector() *FakeCollector {
	return &FakeCollector{start: time.Now()}
}

func (f *FakeCollector) Collect() ([]Interface, error) {
	now := time.Now()
	elapsed := now.Sub(f.start)

	// Healthy handshake: fresh, jittering a little to look alive.
	fresh := now.Add(-time.Duration(int(elapsed.Seconds())%18) * time.Second)
	// Steadily growing counters keyed off elapsed seconds.
	grow := func(base, rate uint64) uint64 { return base + uint64(elapsed.Seconds())*rate }

	flap := f.start // flapping peer's handshake, frozen at startup

	return []Interface{
		{
			Name: "wg0", PublicKey: "SrvWg0PubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0=", ListenPort: 51820,
			Peers: []Peer{
				{Interface: "wg0", PublicKey: "Office1PubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAA01=",
					Endpoint: "8.8.8.8:51820", AllowedIPs: []string{"10.10.0.2/32"},
					LastHandshake: fresh, RxBytes: grow(8_400_000, 2300), TxBytes: grow(3_100_000, 1700), PersistentKeepalive: 25},
			},
		},
		{
			Name: "wg2", PublicKey: "SrvWg2PubKeyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB2=", ListenPort: 51821,
			Peers: []Peer{
				{Interface: "wg2", PublicKey: "Office2PubKeyBBBBBBBBBBBBBBBBBBBBBBBBBBBB02=",
					Endpoint: "1.1.1.1:51820", AllowedIPs: []string{"10.20.0.2/32"},
					LastHandshake: fresh.Add(-3 * time.Second), RxBytes: grow(15_900_000, 4100), TxBytes: grow(6_700_000, 2600), PersistentKeepalive: 25},
			},
		},
		{
			Name: "wg-mesh", PublicKey: "MeshHubPubKeyCCCCCCCCCCCCCCCCCCCCCCCCCCCCC3=", ListenPort: 51830,
			Peers: []Peer{
				{Interface: "wg-mesh", PublicKey: "MeshVpcAPubKeyCCCCCCCCCCCCCCCCCCCCCCCCCC03=",
					Endpoint: "9.9.9.9:51830", AllowedIPs: []string{"10.40.0.0/16"},
					LastHandshake: fresh.Add(-9 * time.Second), RxBytes: grow(42_300_000, 5200), TxBytes: grow(38_100_000, 4900), PersistentKeepalive: 25},
				// The flapping peer: handshake frozen at last recovery.
				{Interface: "wg-mesh", PublicKey: "MeshVpcBPubKeyDDDDDDDDDDDDDDDDDDDDDDDDDD04=",
					Endpoint: "208.67.222.222:51830", AllowedIPs: []string{"10.41.0.0/16"},
					LastHandshake: flap, RxBytes: 27_500_000, TxBytes: 19_200_000, PersistentKeepalive: 25},
			},
		},
		{
			Name: "wg-mesh-stg", PublicKey: "MeshStgPubKeyEEEEEEEEEEEEEEEEEEEEEEEEEEEEE5=", ListenPort: 51831,
			Peers: []Peer{
				{Interface: "wg-mesh-stg", PublicKey: "StgRemotePubKeyEEEEEEEEEEEEEEEEEEEEEEEEE05=",
					Endpoint: "8.8.4.4:51831", AllowedIPs: []string{"10.50.0.0/16"},
					LastHandshake: fresh.Add(-12 * time.Second), RxBytes: grow(5_100_000, 900), TxBytes: grow(4_400_000, 800), PersistentKeepalive: 25},
			},
		},
	}, nil
}
