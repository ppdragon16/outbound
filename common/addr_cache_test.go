package common

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func newTestCache(t *testing.T, ttl time.Duration, seed []net.Addr, resolve func() ([]net.Addr, error)) *AddrCache {
	t.Helper()
	c := NewAddrCache(seed, resolve)
	c.TTL = ttl
	return c
}

func udpAddrs(ips ...string) []net.Addr {
	out := make([]net.Addr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, &net.UDPAddr{IP: net.ParseIP(ip), Port: 443})
	}
	return out
}

func assertAddrs(t *testing.T, got []net.Addr, want ...string) {
	t.Helper()
	gotStr := make([]string, 0, len(got))
	for _, a := range got {
		gotStr = append(gotStr, a.String())
	}
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
func TestAddrCache_ReuseWithinTTL(t *testing.T) {
	calls := 0
	c := newTestCache(t, time.Hour, udpAddrs("10.0.0.1"), func() ([]net.Addr, error) {
		calls++
		return udpAddrs("10.0.0.2"), nil
	})
	for i := 0; i < 3; i++ {
		addrs, err := c.Get()
		if err != nil {
			t.Fatalf("Get() = %v", err)
		}
		assertAddrs(t, addrs, "10.0.0.1:443")
		c.Report(true)
	}
	if calls != 0 {
		t.Fatalf("resolver called %d times within TTL after success, want 0", calls)
	}
}

// Healing: after a failed connect the next Get must re-resolve and return the
// fresh list, so a rotated server entry heals on the next connect cycle.
func TestAddrCache_RefreshAfterFailure(t *testing.T) {
	live := udpAddrs("203.0.113.10")
	calls := 0
	c := newTestCache(t, time.Hour, udpAddrs("198.51.100.1"), func() ([]net.Addr, error) {
		calls++
		return live, nil
	})

	addrs, err := c.Get()
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	assertAddrs(t, addrs, "198.51.100.1:443")

	// The connect using the stale seed failed.
	c.Report(false)

	addrs, err = c.Get()
	if err != nil {
		t.Fatalf("Get() after failure = %v", err)
	}
	assertAddrs(t, addrs, "203.0.113.10:443")
	if calls != 1 {
		t.Fatalf("resolver calls = %d, want 1 (one forced refresh)", calls)
	}

	// The successful connect stabilizes the cache again.
	c.Report(true)
	if _, err = c.Get(); err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if calls != 1 {
		t.Fatalf("resolver calls = %d, want 1 (no refresh after success)", calls)
	}
}

// TTL expiry forces a refresh even on the happy path.
func TestAddrCache_RefreshAfterTTL(t *testing.T) {
	calls := 0
	c := newTestCache(t, 20*time.Millisecond, udpAddrs("10.0.0.1"), func() ([]net.Addr, error) {
		calls++
		return udpAddrs(fmt.Sprintf("10.0.0.%d", calls)), nil
	})
	if _, err := c.Get(); err != nil {
		t.Fatalf("Get() = %v", err)
	}
	c.Report(true)
	time.Sleep(50 * time.Millisecond)
	addrs, err := c.Get()
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	assertAddrs(t, addrs, "10.0.0.1:443") // resolver's 1st call: calls increments to 1 -> "10.0.0.1"
	if calls != 1 {
		t.Fatalf("resolver calls = %d, want 1 (refresh after TTL)", calls)
	}
}

// A failed re-resolution must not break the connect: fall back to the cached
// list so a DNS hiccup doesn't take down an otherwise workable dialer.
func TestAddrCache_FallbackOnResolveError(t *testing.T) {
	calls := 0
	c := newTestCache(t, time.Hour, udpAddrs("10.0.0.1"), func() ([]net.Addr, error) {
		calls++
		if calls > 1 {
			return nil, errors.New("dns down")
		}
		return udpAddrs("10.0.0.1"), nil
	})
	if _, err := c.Get(); err != nil {
		t.Fatalf("Get() = %v", err)
	}
	c.Report(false) // previous connect failed -> next Get re-resolves
	addrs, err := c.Get()
	if err != nil {
		t.Fatalf("Get() with failing resolver = %v, want fallback to cache", err)
	}
	assertAddrs(t, addrs, "10.0.0.1:443")
}

// Empty resolution result is treated like an error when there is nothing to
// fall back on.
func TestAddrCache_EmptyResolutionNoCache(t *testing.T) {
	c := newTestCache(t, time.Hour, nil, func() ([]net.Addr, error) {
		return nil, nil
	})
	if _, err := c.Get(); err == nil {
		t.Fatal("Get() with empty cache and empty resolution should error")
	}
}

// Without a resolver, the cache serves the frozen seed forever: legacy
// behavior for callers that only populate the initial list.
func TestAddrCache_FrozenWithoutResolver(t *testing.T) {
	c := NewAddrCache(udpAddrs("10.0.0.1"), nil)
	addrs, err := c.Get()
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	assertAddrs(t, addrs, "10.0.0.1:443")
}
