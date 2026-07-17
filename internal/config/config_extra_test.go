package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DigitalTolk/wireguard-status/internal/auth"
)

func validHash(t *testing.T) string {
	t.Helper()
	h, err := auth.Hash("pw")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestApplyEnvValid(t *testing.T) {
	t.Setenv("WG_LISTEN", ":9000")
	t.Setenv("WG_COLLECTOR", "fake")
	t.Setenv("WG_TLS_CERT", "/tls/cert.pem")
	t.Setenv("WG_TLS_KEY", "/tls/key.pem")
	t.Setenv("WG_AUTH_USER", "bob")
	t.Setenv("WG_AUTH_PASS", "pw")
	t.Setenv("WG_AUTH_PASS_HASH", "somehash")
	t.Setenv("WG_HANDSHAKE_STALE", "30s")
	t.Setenv("WG_POLL_INTERVAL", "2s")

	c := Defaults()
	c.applyEnv()

	if c.Listen != ":9000" || c.Collector != "fake" || c.Auth.Username != "bob" ||
		c.Auth.Password != "pw" || c.Auth.PasswordHash != "somehash" ||
		c.TLSCert != "/tls/cert.pem" || c.TLSKey != "/tls/key.pem" {
		t.Errorf("string env overrides not applied: %+v", c)
	}
	if c.Thresholds.HandshakeStale.D() != 30*time.Second || c.PollInterval.D() != 2*time.Second {
		t.Errorf("typed env overrides not applied: %+v", c)
	}
}

func TestApplyEnvInvalidValuesIgnored(t *testing.T) {
	t.Setenv("WG_HANDSHAKE_STALE", "nope")
	t.Setenv("WG_POLL_INTERVAL", "nope")

	c := Defaults()
	before := *c
	c.applyEnv()

	if c.Thresholds.HandshakeStale != before.Thresholds.HandshakeStale ||
		c.PollInterval != before.PollInterval {
		t.Error("invalid env values should be ignored, leaving defaults intact")
	}
}

func TestValidate(t *testing.T) {
	good := func() *Config {
		c := Defaults()
		c.Auth.PasswordHash = validHash(t)
		return c
	}
	if err := good().validate(); err != nil {
		t.Fatalf("baseline config should validate: %v", err)
	}

	cases := map[string]func(*Config){
		"unknown collector": func(c *Config) { c.Collector = "bogus" },
		"empty username":    func(c *Config) { c.Auth.Username = "" },
		"no password hash":  func(c *Config) { c.Auth.PasswordHash = "" },
		"stale non-positive": func(c *Config) {
			c.Thresholds.HandshakeStale = 0
		},
		"poll non-positive":    func(c *Config) { c.PollInterval = 0 },
		"tls cert without key": func(c *Config) { c.TLSCert = "/cert.pem" },
		"tls key without cert": func(c *Config) { c.TLSKey = "/key.pem" },
	}
	for name, brk := range cases {
		t.Run(name, func(t *testing.T) {
			c := good()
			brk(c)
			if err := c.validate(); err == nil {
				t.Errorf("%s should fail validation", name)
			}
		})
	}
}

func TestResolveAuthErrors(t *testing.T) {
	// No hash and no password.
	c := &Config{}
	c.Auth.Username = "a"
	if err := c.resolveAuth(); err == nil {
		t.Error("missing password and hash should error")
	}

	// hashFn failure surfaces.
	orig := hashFn
	t.Cleanup(func() { hashFn = orig })
	hashFn = func(string) (string, error) { return "", errors.New("rng down") }
	c2 := &Config{}
	c2.Auth.Password = "pw"
	if err := c2.resolveAuth(); err == nil {
		t.Error("hash failure should surface from resolveAuth")
	}
}

func TestParseINITLS(t *testing.T) {
	c := Defaults()
	if err := c.parseINI([]byte("[Server]\nTLSCert = /etc/tls/cert.pem\nTLSKey = /etc/tls/key.pem\n")); err != nil {
		t.Fatalf("parseINI: %v", err)
	}
	if c.TLSCert != "/etc/tls/cert.pem" || c.TLSKey != "/etc/tls/key.pem" {
		t.Errorf("TLS keys not parsed: cert=%q key=%q", c.TLSCert, c.TLSKey)
	}
}

func TestString(t *testing.T) {
	if s := Defaults().String(); !contains(s, "listen=") || !contains(s, "tls=off") {
		t.Errorf("String() = %q, missing expected fields", s)
	}
	c := Defaults()
	c.TLSCert, c.TLSKey = "/c.pem", "/k.pem"
	if s := c.String(); !contains(s, "tls=on") {
		t.Errorf("String() with TLS = %q, want tls=on", s)
	}
}

func TestLoadEdgeCases(t *testing.T) {
	dir := t.TempDir()

	// Empty path: defaults + env only, still valid.
	if _, err := Load(""); err != nil {
		t.Errorf("Load(\"\") should succeed on defaults: %v", err)
	}

	// Missing file: not an error, falls through to defaults.
	if _, err := Load(filepath.Join(dir, "does-not-exist.conf")); err != nil {
		t.Errorf("missing file should not error: %v", err)
	}

	// A directory is a read error that is neither nil nor ErrNotExist.
	if _, err := Load(dir); err == nil {
		t.Error("reading a directory as config should error")
	}

	// Malformed INI surfaces a parse error.
	bad := filepath.Join(dir, "bad.conf")
	if err := os.WriteFile(bad, []byte("not a section line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Error("malformed INI should fail to load")
	}

	// A config that clears the password fails auth resolution.
	nopass := filepath.Join(dir, "nopass.conf")
	if err := os.WriteFile(nopass, []byte("[Auth]\nUsername = a\nPassword =\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(nopass); err == nil {
		t.Error("empty password with no hash should fail to load")
	}
}

func TestParseINIMoreErrors(t *testing.T) {
	cases := map[string]string{
		"unterminated header": "[Server\nListen = :80\n",
		"empty header":        "[]\nKey = v\n",
		"bad pollinterval":    "[Server]\nPollInterval = soon\n",
		"bad handshakestale":  "[Monitor]\nHandshakeStale = soon\n",
		"server unknown key":  "[Server]\nNope = v\n",
		"auth unknown key":    "[Auth]\nNope = v\n",
		"monitor unknown key": "[Monitor]\nNope = v\n",
		// A token longer than bufio's 64KiB buffer makes the scanner error,
		// exercising the sc.Err() path in parseSections.
		"scanner error": strings.Repeat("a", 70000),
	}
	for name, ini := range cases {
		t.Run(name, func(t *testing.T) {
			c := Defaults()
			if err := c.parseINI([]byte(ini)); err == nil {
				t.Errorf("expected error for %q", name)
			}
		})
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
