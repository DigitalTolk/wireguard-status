// Package config loads runtime configuration from a WireGuard-style INI file
// (sections in [Brackets], Key = Value lines) with environment-variable
// overrides. It is intentionally dependency-free.
package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/DigitalTolk/wireguard-status/internal/auth"
)

// Duration wraps time.Duration so it can be parsed from a Go duration string
// such as "180s" or "5m".
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

// Config is the full application configuration.
type Config struct {
	// Listen is the HTTP listen address, e.g. ":8080".
	Listen string

	// Collector selects the data source: "wg" (real) or "fake" (demo).
	Collector string

	Auth struct {
		Username string
		// Password is an optional plaintext password (dev convenience). When set
		// and PasswordHash is empty, it is hashed in memory at startup.
		Password string
		// PasswordHash is the stored PBKDF2 hash (see internal/auth). This is
		// what is actually used to verify requests; never plaintext on disk.
		PasswordHash string
	}

	Thresholds struct {
		// HandshakeStale: a peer whose latest handshake is older than this
		// is considered down.
		HandshakeStale Duration
	}

	// PollInterval is how often the background monitor refreshes state.
	PollInterval Duration

	AutoRestart struct {
		Enabled bool
		// DownFor: an interface must have a peer continuously down for at least
		// this long before an automatic restart is attempted.
		DownFor Duration
		// Cooldown: minimum interval between restart attempts for one interface.
		Cooldown Duration
		// MaxAttempts: give up after this many attempts until the link recovers.
		MaxAttempts int
	}

	Restart struct {
		// Command is the restart command. "{iface}" is replaced with the
		// interface name. Ignored in fake mode.
		Command []string
	}
}

// Defaults returns a config populated with sane defaults.
func Defaults() *Config {
	c := &Config{
		Listen:    ":8080",
		Collector: "wg",
	}
	c.Auth.Username = "admin"
	c.Auth.Password = "changeme"
	c.Thresholds.HandshakeStale = Duration(180 * time.Second)
	c.PollInterval = Duration(5 * time.Second)
	c.AutoRestart.Enabled = true
	c.AutoRestart.DownFor = Duration(5 * time.Minute)
	c.AutoRestart.Cooldown = Duration(10 * time.Minute)
	c.AutoRestart.MaxAttempts = 3
	c.Restart.Command = []string{"systemctl", "restart", "wg-quick@{iface}"}
	return c
}

// Load reads the INI config at path (if it exists) over the defaults, then
// applies environment overrides. A missing path is not an error.
func Load(path string) (*Config, error) {
	c := Defaults()
	if path != "" {
		b, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := c.parseINI(b); err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
		case errors.Is(err, os.ErrNotExist):
			// fall through to env-only configuration
		default:
			return nil, err
		}
	}
	c.applyEnv()
	if err := c.resolveAuth(); err != nil {
		return nil, err
	}
	return c, c.validate()
}

// resolveAuth produces Auth.PasswordHash. A configured hash wins; otherwise a
// plaintext password is hashed in memory (with a nudge to store a hash on disk).
func (c *Config) resolveAuth() error {
	if c.Auth.PasswordHash != "" {
		if !auth.Valid(c.Auth.PasswordHash) {
			return errors.New("[Auth] PasswordHash is not a valid pbkdf2-sha256 hash (generate one with: wg-status -hash-password)")
		}
		c.Auth.Password = "" // don't keep plaintext around
		return nil
	}
	if c.Auth.Password == "" {
		return errors.New("[Auth] needs PasswordHash (preferred) or Password")
	}
	h, err := auth.Hash(c.Auth.Password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	c.Auth.PasswordHash = h
	c.Auth.Password = ""
	log.Printf("warning: hashing a plaintext password in memory; for production set [Auth] PasswordHash (wg-status -hash-password)")
	return nil
}

func (c *Config) applyEnv() {
	if v := os.Getenv("WG_LISTEN"); v != "" {
		c.Listen = v
	}
	if v := os.Getenv("WG_COLLECTOR"); v != "" {
		c.Collector = v
	}
	if v := os.Getenv("WG_AUTH_USER"); v != "" {
		c.Auth.Username = v
	}
	if v := os.Getenv("WG_AUTH_PASS"); v != "" {
		c.Auth.Password = v
	}
	if v := os.Getenv("WG_AUTH_PASS_HASH"); v != "" {
		c.Auth.PasswordHash = v
	}
	if v := os.Getenv("WG_HANDSHAKE_STALE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Thresholds.HandshakeStale = Duration(d)
		}
	}
	if v := os.Getenv("WG_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.PollInterval = Duration(d)
		}
	}
	if v := os.Getenv("WG_AUTORESTART"); v != "" {
		if b, err := parseBool(v); err == nil {
			c.AutoRestart.Enabled = b
		}
	}
	if v := os.Getenv("WG_AUTORESTART_DOWNFOR"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.AutoRestart.DownFor = Duration(d)
		}
	}
}

func (c *Config) validate() error {
	switch c.Collector {
	case "wg", "fake":
	default:
		return fmt.Errorf("unknown Collector %q (want \"wg\" or \"fake\")", c.Collector)
	}
	if c.Auth.Username == "" {
		return errors.New("[Auth] Username must be set")
	}
	if !auth.Valid(c.Auth.PasswordHash) {
		return errors.New("[Auth] password is not configured")
	}
	if c.Thresholds.HandshakeStale <= 0 {
		return errors.New("[Monitor] HandshakeStale must be positive")
	}
	if c.PollInterval <= 0 {
		return errors.New("[Server] PollInterval must be positive")
	}
	if c.Collector == "wg" && len(c.Restart.Command) == 0 {
		return errors.New("[Restart] Command must be set when Collector is \"wg\"")
	}
	return nil
}

// String renders a redacted summary for logging.
func (c *Config) String() string {
	return fmt.Sprintf("listen=%s collector=%s stale=%s poll=%s autorestart=%t(downfor=%s,cooldown=%s,max=%d)",
		c.Listen, c.Collector, c.Thresholds.HandshakeStale.D(), c.PollInterval.D(),
		c.AutoRestart.Enabled, c.AutoRestart.DownFor.D(), c.AutoRestart.Cooldown.D(), c.AutoRestart.MaxAttempts)
}
