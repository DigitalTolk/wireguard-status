package web

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

func TestDNSResolverSuccessAndCache(t *testing.T) {
	var calls atomic.Int32
	r := newDNSResolver(time.Hour)
	r.lookup = func(string) ([]string, error) {
		calls.Add(1)
		return []string{"gw.example.com."}, nil
	}

	// An empty endpoint resolves to no name and never hits the network.
	if got := r.name(""); got != "" {
		t.Errorf("name(\"\") = %q, want empty", got)
	}

	// First call schedules a background lookup and returns empty.
	if got := r.name("203.0.113.5:51820"); got != "" {
		t.Errorf("first call = %q, want empty", got)
	}
	waitFor(t, func() bool { return r.name("203.0.113.5:51820") == "gw.example.com" })

	// Now cached and fresh: no further lookups.
	before := calls.Load()
	for range 3 {
		_ = r.name("203.0.113.5:51820")
	}
	if after := calls.Load(); after != before {
		t.Errorf("fresh cache triggered %d extra lookups", after-before)
	}
}

func TestDNSResolverError(t *testing.T) {
	r := newDNSResolver(time.Hour)
	r.lookup = func(string) ([]string, error) { return nil, errors.New("nxdomain") }
	_ = r.name("198.51.100.9:51820")
	waitFor(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		_, ok := r.cache["198.51.100.9"]
		return ok
	})
	if got := r.name("198.51.100.9:51820"); got != "" {
		t.Errorf("failed lookup should cache an empty name, got %q", got)
	}
}

func TestDNSResolverStaleRefreshes(t *testing.T) {
	r := newDNSResolver(time.Hour)
	r.lookup = func(string) ([]string, error) { return []string{"fresh.example."}, nil }

	// Seed an already-expired entry directly, then confirm it re-resolves.
	r.mu.Lock()
	r.cache["203.0.113.1"] = dnsEntry{name: "old.example", exp: time.Now().Add(-time.Minute)}
	r.mu.Unlock()

	_ = r.name("203.0.113.1:1") // stale -> schedules a background refresh
	waitFor(t, func() bool { return r.name("203.0.113.1:1") == "fresh.example" })
}

func TestDNSResolverInflightDedup(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	r := newDNSResolver(time.Hour)
	r.lookup = func(string) ([]string, error) {
		calls.Add(1)
		<-release
		return []string{"h.example."}, nil
	}

	r.name("192.0.2.1:1") // schedules; the goroutine blocks inside lookup
	waitFor(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		_, busy := r.inflight["192.0.2.1"]
		return busy
	})
	r.name("192.0.2.1:1") // in-flight: must not schedule a second lookup
	close(release)
	waitFor(t, func() bool { return r.name("192.0.2.1:1") == "h.example" })

	if n := calls.Load(); n != 1 {
		t.Errorf("expected exactly one lookup, got %d", n)
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"203.0.113.5:51820":   "203.0.113.5",
		"[2001:db8::1]:51820": "2001:db8::1",
		"bare-host":           "bare-host", // no port -> treated as the host
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
