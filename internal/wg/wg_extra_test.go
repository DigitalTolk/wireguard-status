package wg

import (
	"errors"
	"net"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// fakeClient is an in-memory wgClient for exercising WgCollector without a live
// netlink connection.
type fakeClient struct {
	devices []*wgtypes.Device
	err     error
}

func (f fakeClient) Devices() ([]*wgtypes.Device, error) { return f.devices, f.err }
func (f fakeClient) Close() error                        { return nil }

func withClient(t *testing.T, mk func() (wgClient, error)) {
	t.Helper()
	orig := newWGClient
	t.Cleanup(func() { newWGClient = orig })
	newWGClient = mk
}

func TestWgCollectorNewError(t *testing.T) {
	withClient(t, func() (wgClient, error) { return nil, errors.New("no netlink") })
	if _, err := (WgCollector{}).Collect(); err == nil {
		t.Fatal("Collect should fail when the client cannot be created")
	}
}

func TestWgCollectorDevicesError(t *testing.T) {
	withClient(t, func() (wgClient, error) { return fakeClient{err: errors.New("boom")}, nil })
	if _, err := (WgCollector{}).Collect(); err == nil {
		t.Fatal("Collect should fail when Devices() errors")
	}
}

func TestWgCollectorSuccess(t *testing.T) {
	_, allowed, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	dev := &wgtypes.Device{
		Name:       "wg0",
		ListenPort: 51820,
		Peers: []wgtypes.Peer{{
			Endpoint:   &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 51820},
			AllowedIPs: []net.IPNet{*allowed},
		}},
	}
	withClient(t, func() (wgClient, error) { return fakeClient{devices: []*wgtypes.Device{dev}}, nil })

	ifaces, err := (WgCollector{}).Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(ifaces) != 1 || ifaces[0].Name != "wg0" || len(ifaces[0].Peers) != 1 {
		t.Fatalf("unexpected interfaces: %+v", ifaces)
	}
}

// TestNewWGClientDefault invokes the real (non-overridden) seam so its body
// (wgctrl.New()) is exercised. Whether it succeeds is environment-dependent;
// either way the line runs. Any client is closed to avoid leaking a socket.
func TestNewWGClientDefault(t *testing.T) {
	c, err := newWGClient()
	if err != nil {
		return
	}
	_ = c.Close()
}

func TestCmdRestarterEmptyCommand(t *testing.T) {
	if err := (CmdRestarter{}).Restart("wg0"); err == nil {
		t.Fatal("empty command should error")
	}
}

func TestCmdRestarterCommandFails(t *testing.T) {
	// `false` exits non-zero, so Restart must surface an error.
	r := CmdRestarter{Command: []string{"false"}}
	if err := r.Restart("wg0"); err == nil {
		t.Fatal("failing command should error")
	}
}

func TestFakeCollector(t *testing.T) {
	fc := NewFakeCollector()

	ifaces, err := fc.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(ifaces) == 0 {
		t.Fatal("fake collector returned no interfaces")
	}

	if err := fc.Restart("wg-mesh"); err != nil {
		t.Errorf("restart of known interface: %v", err)
	}
	if err := fc.Restart("nope"); err == nil {
		t.Error("restart of unknown interface should error")
	}
}
