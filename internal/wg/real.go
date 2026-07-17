package wg

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgClient is the subset of *wgctrl.Client that WgCollector uses. Abstracting
// it behind an interface lets tests inject a fake in place of a live netlink
// connection.
type wgClient interface {
	Devices() ([]*wgtypes.Device, error)
	Close() error
}

// newWGClient is a seam over wgctrl.New so tests can substitute a fake client.
var newWGClient = func() (wgClient, error) { return wgctrl.New() }

// WgCollector reads live WireGuard state via the kernel netlink API using the
// official wgctrl library, so it needs neither the `wg` binary nor any text
// parsing.
type WgCollector struct{}

func (c WgCollector) Collect() ([]Interface, error) {
	client, err := newWGClient()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	defer func() { _ = client.Close() }()

	devices, err := client.Devices()
	if err != nil {
		return nil, fmt.Errorf("wgctrl devices: %w", err)
	}

	ifaces := make([]Interface, 0, len(devices))
	for _, d := range devices {
		ifaces = append(ifaces, convertDevice(d))
	}
	return ifaces, nil
}

// convertDevice maps a wgctrl device and its peers onto our model.
func convertDevice(d *wgtypes.Device) Interface {
	iface := Interface{
		Name:       d.Name,
		PublicKey:  d.PublicKey.String(),
		ListenPort: d.ListenPort,
		Peers:      make([]Peer, 0, len(d.Peers)),
	}
	for _, p := range d.Peers {
		iface.Peers = append(iface.Peers, convertPeer(d.Name, p))
	}
	return iface
}

func convertPeer(iface string, p wgtypes.Peer) Peer {
	out := Peer{
		Interface:           iface,
		PublicKey:           p.PublicKey.String(),
		RxBytes:             uint64(p.ReceiveBytes),
		TxBytes:             uint64(p.TransmitBytes),
		PersistentKeepalive: int(p.PersistentKeepaliveInterval.Seconds()),
	}
	// wgctrl reports a zero time for peers that have never handshaked, which
	// matches our "zero means never" convention.
	if !p.LastHandshakeTime.IsZero() {
		out.LastHandshake = p.LastHandshakeTime
	}
	if p.Endpoint != nil {
		out.Endpoint = p.Endpoint.String()
	}
	for _, ipnet := range p.AllowedIPs {
		out.AllowedIPs = append(out.AllowedIPs, ipnet.String())
	}
	return out
}

// CmdRestarter restarts an interface by running a configured command, with
// "{iface}" substituted for the interface name.
type CmdRestarter struct {
	Command []string
}

func (r CmdRestarter) Restart(iface string) error {
	if len(r.Command) == 0 {
		return fmt.Errorf("no restart command configured")
	}
	args := make([]string, len(r.Command))
	for i, a := range r.Command {
		args[i] = strings.ReplaceAll(a, "{iface}", iface)
	}
	cmd := exec.Command(args[0], args[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
