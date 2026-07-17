package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DigitalTolk/wireguard-status/internal/auth"
)

func TestParseINI(t *testing.T) {
	ini := `
# wg-status config
[Server]
Listen       = :8600
Collector    = fake
PollInterval = 2s

[Auth]
Username = bob
Password = hunter2

[Monitor]
HandshakeStale = 90s
`
	c := Defaults()
	if err := c.parseINI([]byte(ini)); err != nil {
		t.Fatalf("parseINI: %v", err)
	}

	if c.Listen != ":8600" || c.Collector != "fake" || c.PollInterval.D() != 2*time.Second {
		t.Errorf("[Server] wrong: listen=%s collector=%s poll=%s", c.Listen, c.Collector, c.PollInterval.D())
	}
	if c.Auth.Username != "bob" || c.Auth.Password != "hunter2" {
		t.Errorf("[Auth] wrong: %+v", c.Auth)
	}
	if c.Thresholds.HandshakeStale.D() != 90*time.Second {
		t.Errorf("HandshakeStale wrong: %s", c.Thresholds.HandshakeStale.D())
	}
}

func TestParseINIErrors(t *testing.T) {
	cases := map[string]string{
		"unknown section": "[Bogus]\nKey = v\n",
		"unknown key":     "[Server]\nNope = v\n",
		"key before sect": "Listen = :80\n",
		"bad duration":    "[Monitor]\nHandshakeStale = soon\n",
		"peer rejected":   "[Peer]\nPublicKey = x\n",
		"iface rejected":  "[Interface]\nName = wg0\n",
		"no equals":       "[Server]\nListen\n",
	}
	for name, ini := range cases {
		t.Run(name, func(t *testing.T) {
			c := Defaults()
			if err := c.parseINI([]byte(ini)); err == nil {
				t.Errorf("expected error for %q, got nil", name)
			}
		})
	}
}

func TestLoadResolvesPassword(t *testing.T) {
	dir := t.TempDir()

	// Plaintext password -> hashed in memory, never stored as plaintext.
	plain := filepath.Join(dir, "plain.conf")
	if err := os.WriteFile(plain, []byte("[Auth]\nUsername = a\nPassword = pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(plain)
	if err != nil {
		t.Fatalf("load plain: %v", err)
	}
	if c.Auth.Password != "" {
		t.Errorf("plaintext password should be cleared after resolution")
	}
	if !auth.Verify(c.Auth.PasswordHash, "pw") {
		t.Errorf("resolved hash should verify the original password")
	}

	// A pre-hashed password is used verbatim.
	h, _ := auth.Hash("secret")
	hashed := filepath.Join(dir, "hashed.conf")
	if err := os.WriteFile(hashed, []byte("[Auth]\nUsername = a\nPasswordHash = "+h+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c2, err := Load(hashed)
	if err != nil {
		t.Fatalf("load hashed: %v", err)
	}
	if c2.Auth.PasswordHash != h || !auth.Verify(c2.Auth.PasswordHash, "secret") {
		t.Errorf("configured hash should be used as-is")
	}

	// An invalid hash is rejected.
	bad := filepath.Join(dir, "bad.conf")
	if err := os.WriteFile(bad, []byte("[Auth]\nUsername = a\nPasswordHash = not-a-hash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Errorf("invalid PasswordHash should fail to load")
	}
}

// The shipped example config must parse and validate.
func TestExampleConfigValidates(t *testing.T) {
	path := filepath.Join("..", "..", "wg-status.example.conf")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("example not found: %v", err)
	}
	c := Defaults()
	if err := c.parseINI(b); err != nil {
		t.Fatalf("example parseINI: %v", err)
	}
	// The example uses the real collector with a restart command, so it should
	// pass validation as-is.
	if err := c.validate(); err != nil {
		t.Fatalf("example validate: %v", err)
	}
}
