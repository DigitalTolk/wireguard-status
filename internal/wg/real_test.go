package wg

import (
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestConvertDevice(t *testing.T) {
	_, allowed, err := net.ParseCIDR("10.40.0.0/16")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	dev := &wgtypes.Device{
		Name:       "wg-mesh",
		ListenPort: 51830,
		Peers: []wgtypes.Peer{
			{
				Endpoint:                    &net.UDPAddr{IP: net.ParseIP("203.0.113.40"), Port: 51830},
				AllowedIPs:                  []net.IPNet{*allowed},
				LastHandshakeTime:           time.Unix(1700000100, 0),
				ReceiveBytes:                42300000,
				TransmitBytes:               38100000,
				PersistentKeepaliveInterval: 0,
			},
			{
				// never handshaked, no endpoint, keepalive on
				LastHandshakeTime:           time.Time{},
				PersistentKeepaliveInterval: 25 * time.Second,
			},
		},
	}

	iface := convertDevice(dev)
	if iface.Name != "wg-mesh" || iface.ListenPort != 51830 {
		t.Errorf("interface header wrong: %+v", iface)
	}
	if len(iface.Peers) != 2 {
		t.Fatalf("want 2 peers, got %d", len(iface.Peers))
	}

	pa := iface.Peers[0]
	if pa.Interface != "wg-mesh" {
		t.Errorf("peerA interface wrong: %q", pa.Interface)
	}
	if pa.Endpoint != "203.0.113.40:51830" || pa.RxBytes != 42300000 || pa.TxBytes != 38100000 {
		t.Errorf("peerA fields wrong: %+v", pa)
	}
	if len(pa.AllowedIPs) != 1 || pa.AllowedIPs[0] != "10.40.0.0/16" {
		t.Errorf("peerA allowed-ips wrong: %v", pa.AllowedIPs)
	}
	if !pa.LastHandshake.Equal(time.Unix(1700000100, 0)) {
		t.Errorf("peerA handshake wrong: %v", pa.LastHandshake)
	}

	// peerB: never handshaked, no endpoint, keepalive on.
	pb := iface.Peers[1]
	if !pb.LastHandshake.IsZero() {
		t.Errorf("peerB should have zero handshake, got %v", pb.LastHandshake)
	}
	if pb.Endpoint != "" || pb.AllowedIPs != nil {
		t.Errorf("peerB should have empty endpoint/allowed-ips: %+v", pb)
	}
	if pb.PersistentKeepalive != 25 {
		t.Errorf("peerB keepalive wrong: %d", pb.PersistentKeepalive)
	}
}

func TestCmdRestarterSubstitutesIface(t *testing.T) {
	r := CmdRestarter{Command: []string{"echo", "restart", "{iface}"}}
	if err := r.Restart("wg-mesh"); err != nil {
		t.Fatalf("restart: %v", err)
	}
}
