package client

import (
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/pkg/oops"
)

// defaultAddrsTTL bounds how long a resolved candidate list is reused on the
// happy path. It only limits staleness for otherwise-healthy tunnels: failed
// connects always trigger a re-resolution (see addrsCache.report), so a rotated
// server entry heals within one reconnect instead of the full TTL.
const defaultAddrsTTL = 5 * time.Minute

// addrsCache turns the candidate list from a build-time snapshot into a
// refresh-on-demand one. Historically Config.Addrs was resolved once when the
// dialer was built and every Connect re-dialed the same (possibly long-dead)
// IPs until the whole daemon restarted; providers that rotate entry IPs or
// flaky address families (e.g. unstable IPv6) then bricked the dialer.
//
// Refresh rules (get):
//   - cache fresh AND previous connect succeeded -> reuse cache (happy path
//     pays zero DNS round trips);
//   - cache stale OR previous connect failed      -> re-resolve;
//   - re-resolution fails                         -> fall back to the cached
//     list, so a DNS hiccup never breaks an otherwise workable connect.
type addrsCache struct {
	mu      sync.Mutex
	resolve func() ([]net.Addr, error)
	ttl     time.Duration

	addrs    []net.Addr
	fetched  time.Time
	lastFail bool
}

func newAddrsCache(seed []net.Addr, resolve func() ([]net.Addr, error)) *addrsCache {
	return &addrsCache{
		resolve: resolve,
		ttl:     defaultAddrsTTL,
		addrs:   seed,
		fetched: time.Now(),
	}
}

// get returns the candidate list to race this connect attempt with.
func (a *addrsCache) get() ([]net.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.resolve == nil {
		// No server address configured (build-time snapshot only): frozen
		// candidates, legacy behavior.
		return a.addrs, nil
	}
	stale := time.Since(a.fetched) > a.ttl
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
		return nil, oops.In("Hysteria2").New("server host resolved to no addresses")
	}
	a.addrs = fresh
	a.fetched = time.Now()
	a.lastFail = false
	return a.addrs, nil
}

// report records the outcome of the connect that used the list returned by
// get; a failed connect forces the next get to re-resolve.
func (a *addrsCache) report(success bool) {
	a.mu.Lock()
	a.lastFail = !success
	a.mu.Unlock()
}
