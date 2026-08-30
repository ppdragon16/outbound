package client

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// newTestCache builds an addrsCache with an injectable resolver and TTL.
func newTestCache(t *testing.T, ttl time.Duration, seed []net.Addr, resolve func() ([]net.Addr, error)) *addrsCache {
	t.Helper()
	c := newAddrsCache(seed, resolve)
	c.ttl = ttl
	return c
}

func udpAddrs(ips ...string) []net.Addr {
	out := make([]net.Addr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, &net.UDPAddr{IP: net.ParseIP(ip), Port: 443})
	}
	return out
}

func addrStrings(addrs []net.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

func assertAddrs(t *testing.T, got []net.Addr, want ...string) {
	t.Helper()
	gotStr := addrStrings(got)
	if len(gotStr) != len(want) {
		t.Fatalf("candidate count = %d (%v), want %d (%v)", len(gotStr), gotStr, len(want), want)
	}
	for i := range want {
		if gotStr[i] != want[i] {
			t.Fatalf("candidate[%d] = %q, want %q (all: %v)", i, gotStr[i], want[i], gotStr)
		}
	}
}

// Happy path: within the TTL and after a successful connect, the cache serves
// the same list without calling the resolver again.
func TestAddrsCache_ReuseWithinTTL(t *testing.T) {
	calls := 0
	c := newTestCache(t, time.Hour, udpAddrs("10.0.0.1"), func() ([]net.Addr, error) {
		calls++
		return udpAddrs("10.0.0.2"), nil
	})
	for i := 0; i < 3; i++ {
		addrs, err := c.get()
		if err != nil {
			t.Fatalf("get() = %v", err)
		}
		assertAddrs(t, addrs, "10.0.0.1:443")
		c.report(true)
	}
	if calls != 0 {
		t.Fatalf("resolver called %d times within TTL after success, want 0", calls)
	}
}

// Healing: after a failed connect the next get must re-resolve and return the
// fresh list, so a rotated server entry heals on the next connect cycle.
func TestAddrsCache_RefreshAfterFailure(t *testing.T) {
	live := udpAddrs("203.0.113.10")
	calls := 0
	c := newTestCache(t, time.Hour, udpAddrs("198.51.100.1"), func() ([]net.Addr, error) {
		calls++
		return live, nil
	})

	addrs, err := c.get()
	if err != nil {
		t.Fatalf("get() = %v", err)
	}
	assertAddrs(t, addrs, "198.51.100.1:443")

	// The connect using the stale seed failed.
	c.report(false)

	addrs, err = c.get()
	if err != nil {
		t.Fatalf("get() after failure = %v", err)
	}
	assertAddrs(t, addrs, "203.0.113.10:443")
	if calls != 1 {
		t.Fatalf("resolver calls = %d, want 1 (one forced refresh)", calls)
	}

	// The successful connect stabilizes the cache again.
	c.report(true)
	if _, err = c.get(); err != nil {
		t.Fatalf("get() = %v", err)
	}
	if calls != 1 {
		t.Fatalf("resolver calls = %d, want 1 (no refresh after success)", calls)
	}
}

// TTL expiry forces a refresh even on the happy path.
func TestAddrsCache_RefreshAfterTTL(t *testing.T) {
	calls := 0
	c := newTestCache(t, 20*time.Millisecond, udpAddrs("10.0.0.1"), func() ([]net.Addr, error) {
		calls++
		return udpAddrs(fmt.Sprintf("10.0.0.%d", calls)), nil
	})
	if _, err := c.get(); err != nil {
		t.Fatalf("get() = %v", err)
	}
	c.report(true)
	time.Sleep(50 * time.Millisecond)
	addrs, err := c.get()
	if err != nil {
		t.Fatalf("get() = %v", err)
	}
	assertAddrs(t, addrs, "10.0.0.1:443") // 2nd call: calls increments to 1 -> "10.0.0.1"
	if calls != 1 {
		t.Fatalf("resolver calls = %d, want 1 (refresh after TTL)", calls)
	}
}

// A failed re-resolution must not break the connect: fall back to the cached
// list so a DNS hiccup doesn't take down an otherwise workable dialer.
func TestAddrsCache_FallbackOnResolveError(t *testing.T) {
	calls := 0
	c := newTestCache(t, time.Hour, udpAddrs("10.0.0.1"), func() ([]net.Addr, error) {
		calls++
		if calls > 1 {
			return nil, errors.New("dns down")
		}
		return udpAddrs("10.0.0.1"), nil
	})
	if _, err := c.get(); err != nil {
		t.Fatalf("get() = %v", err)
	}
	c.report(false) // previous connect failed -> next get re-resolves
	addrs, err := c.get()
	if err != nil {
		t.Fatalf("get() with failing resolver = %v, want fallback to cache", err)
	}
	assertAddrs(t, addrs, "10.0.0.1:443")
}

// Empty resolution result is treated like an error when there is nothing to
// fall back on.
func TestAddrsCache_EmptyResolutionNoCache(t *testing.T) {
	c := newTestCache(t, time.Hour, nil, func() ([]net.Addr, error) {
		return nil, nil
	})
	if _, err := c.get(); err == nil {
		t.Fatal("get() with empty cache and empty resolution should error")
	}
}

// Without a resolver (ServerAddr empty), the cache serves the frozen seed
// forever: legacy behavior for callers that only populate Addrs.
func TestAddrsCache_FrozenWithoutResolver(t *testing.T) {
	c := &addrsCache{addrs: udpAddrs("10.0.0.1"), fetched: time.Now()}
	addrs, err := c.get()
	if err != nil {
		t.Fatalf("get() = %v", err)
	}
	assertAddrs(t, addrs, "10.0.0.1:443")
}
