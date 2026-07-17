package web

import (
	"net"
	"strings"
	"sync"
	"time"
)

// dnsResolver caches reverse-DNS (PTR) lookups in process memory for a fixed
// TTL. Lookups run in the background so page rendering never blocks on DNS; a
// resolved name becomes visible on a later auto-refresh.
type dnsResolver struct {
	ttl    time.Duration
	lookup func(string) ([]string, error) // seam over net.LookupAddr

	mu       sync.Mutex
	cache    map[string]dnsEntry
	inflight map[string]struct{}
}

type dnsEntry struct {
	name string
	exp  time.Time
}

func newDNSResolver(ttl time.Duration) *dnsResolver {
	return &dnsResolver{
		ttl:      ttl,
		lookup:   net.LookupAddr,
		cache:    map[string]dnsEntry{},
		inflight: map[string]struct{}{},
	}
}

// name returns the cached reverse-DNS host for an endpoint ("ip:port"),
// scheduling a background lookup when the entry is missing or stale. It returns
// "" until a name is known (or when there is no reverse record).
func (r *dnsResolver) name(endpoint string) string {
	host := hostOf(endpoint)
	if host == "" {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[host]
	if !ok || !time.Now().Before(e.exp) {
		if _, busy := r.inflight[host]; !busy {
			r.inflight[host] = struct{}{}
			go r.resolve(host)
		}
	}
	return e.name
}

func (r *dnsResolver) resolve(host string) {
	names, err := r.lookup(host)
	name := ""
	if err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}
	r.mu.Lock()
	r.cache[host] = dnsEntry{name: name, exp: time.Now().Add(r.ttl)}
	delete(r.inflight, host)
	r.mu.Unlock()
}

// hostOf extracts the host from an "ip:port" endpoint, tolerating a bare host
// and returning "" for an empty endpoint.
func hostOf(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return host
	}
	return endpoint
}
