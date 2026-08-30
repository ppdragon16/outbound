package common

import (
	"errors"
	"net"
	"sync"
	"time"
)

// DefaultAddrCacheTTL bounds how long a resolved candidate list is reused on
// the happy path. It only limits staleness for otherwise-healthy tunnels:
// failed connects always trigger a re-resolution (see AddrCache.Report), so a
// rotated server entry heals within one reconnect instead of the full TTL.
const DefaultAddrCacheTTL = 5 * time.Minute

// AddrCache turns a QUIC dialer's candidate list from a build-time snapshot
// into a refresh-on-demand one. QUIC protocols must resolve the server
// themselves (they own the UDP transport) and historically froze the list at
// dialer construction: providers that rotate entry IPs, or a dead address
// family (e.g. flaky IPv6 with a v6-only snapshot), then bricked the dialer
// until the whole daemon restarted.
//
// Refresh rules (Get):
//   - cache fresh AND previous connect succeeded -> reuse cache (happy path
//     pays zero DNS round trips);
//   - cache stale OR previous connect failed      -> re-resolve;
//   - re-resolution fails                         -> fall back to the cached
//     list, so a DNS hiccup never breaks an otherwise workable connect.
//
// A nil resolve func yields the frozen legacy behavior (seed list forever).
type AddrCache struct {
	mu      sync.Mutex
	resolve func() ([]net.Addr, error)

	// TTL bounds the freshness of the cached list; adjust before first use.
	TTL time.Duration

	addrs    []net.Addr
	fetched  time.Time
	lastFail bool
}

// NewAddrCache seeds the cache with the build-time resolution and the
// re-resolution function (nil disables refreshing).
func NewAddrCache(seed []net.Addr, resolve func() ([]net.Addr, error)) *AddrCache {
	return &AddrCache{
		resolve: resolve,
		TTL:     DefaultAddrCacheTTL,
		addrs:   seed,
		fetched: time.Now(),
	}
}

// Get returns the candidate list to race the next connect attempt with.
func (a *AddrCache) Get() ([]net.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.resolve == nil {
		// No server address configured (build-time snapshot only): frozen
		// candidates, legacy behavior.
		return a.addrs, nil
	}
	stale := time.Since(a.fetched) > a.TTL
	if len(a.addrs) > 0 && !stale && !a.lastFail {
		return a.addrs, nil
	}
	fresh, err := a.resolve()
	if err != nil || len(fresh) == 0 {
		if len(a.addrs) > 0 {
			// Keep serving the previous list; the next failed connect will
			// retry resolution.
			return a.addrs, nil
		}
		if err != nil {
			return nil, err
		}
		return nil, errors.New("resolved to no candidate addresses")
	}
	a.addrs = fresh
	a.fetched = time.Now()
	a.lastFail = false
	return a.addrs, nil
}

// Report records the outcome of the connect that used the list returned by
// Get; a failed connect forces the next Get to re-resolve.
func (a *AddrCache) Report(success bool) {
	a.mu.Lock()
	a.lastFail = !success
	a.mu.Unlock()
}
