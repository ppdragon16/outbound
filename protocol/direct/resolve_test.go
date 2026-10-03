package direct

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// withDirect installs d as the package-level direct dialer for one test.
func withDirect(t *testing.T, d netproxy.Dialer) {
	t.Helper()
	old := Direct
	Direct = d
	t.Cleanup(func() { Direct = old })
}

// blackholedPolicy returns a direct dialer whose system view never answers and
// whose fallback resolver is the stub, i.e. only the policy's race can produce
// an answer.
func blackholedPolicy(t *testing.T, fallback *fakeDNS) *directDialer {
	t.Helper()
	return &directDialer{
		resolver:         resolverTo(newFakeDNS(t, fakeDNSBlackhole)),
		fallbackResolver: resolverTo(fallback),
		option:           Option{CacheTTL: time.Minute},
		dnsCache:         map[string]*dnsCacheEntry{},
	}
}

func TestResolveUDPAddrsUsesDialPolicyForHostname(t *testing.T) {
	withDirect(t, blackholedPolicy(t, newFakeDNS(t, fakeDNSAnswer)))

	addrs, err := ResolveUDPAddrs("node.example.com:443")
	if err != nil {
		t.Fatalf("ResolveUDPAddrs: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("expected both families, got %v", addrs)
	}
	// IPv4 first, and every candidate keeps the requested port.
	first, ok := addrs[0].(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected a UDP address, got %T", addrs[0])
	}
	if !first.IP.Equal(net.ParseIP("4.4.4.4")) || first.Port != 443 {
		t.Fatalf("expected 4.4.4.4:443 first, got %v", first)
	}
	second := addrs[1].(*net.UDPAddr)
	if !second.IP.Equal(net.ParseIP("2001:db8::4")) || second.Port != 443 {
		t.Fatalf("expected [2001:db8::4]:443 second, got %v", second)
	}
}

func TestResolveIPAddrPicksIPv4First(t *testing.T) {
	withDirect(t, blackholedPolicy(t, newFakeDNS(t, fakeDNSAnswer)))

	addr, err := ResolveIPAddr("node.example.com")
	if err != nil {
		t.Fatalf("ResolveIPAddr: %v", err)
	}
	if !addr.IP.Equal(net.ParseIP("4.4.4.4")) {
		t.Fatalf("expected the IPv4 answer, got %v", addr)
	}
}

// TestResolveLiteralSkipsPolicyAndPort covers the no-DNS configuration: a
// literal is answered without consulting the policy, which a dialer that fails
// every lookup makes observable, and the port survives.
func TestResolveLiteralSkipsPolicyAndPort(t *testing.T) {
	withDirect(t, foreignDialer{})

	addrs, err := ResolveUDPAddrs("1.2.3.4:53")
	if err != nil {
		t.Fatalf("ResolveUDPAddrs: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("expected one address, got %v", addrs)
	}
	got := addrs[0].(*net.UDPAddr)
	if !got.IP.Equal(net.ParseIP("1.2.3.4")) || got.Port != 53 {
		t.Fatalf("expected 1.2.3.4:53, got %v", got)
	}

	// A literal with a zone keeps it (link-local addresses need it).
	zoned, err := ResolveUDPAddrs("[fe80::1%eth0]:53")
	if err != nil {
		t.Fatalf("ResolveUDPAddrs: %v", err)
	}
	if z := zoned[0].(*net.UDPAddr); z.Zone != "eth0" || z.Port != 53 {
		t.Fatalf("expected the zone and port to survive, got %v", z)
	}

	// ResolveIPAddrs accepts "host:port" and ignores the port, like the helper
	// it replaces.
	ips, err := ResolveIPAddrs("1.2.3.4:443")
	if err != nil {
		t.Fatalf("ResolveIPAddrs: %v", err)
	}
	if len(ips) != 1 || !ips[0].IP.Equal(net.ParseIP("1.2.3.4")) {
		t.Fatalf("expected the literal back, got %v", ips)
	}
}

// TestResolveNoUsableAnswerIsAnError covers the empty-answer guard: a resolver
// that answers without an address is an error, not a silent nil candidate list.
func TestResolveNoUsableAnswerIsAnError(t *testing.T) {
	withDirect(t, &directDialer{
		resolver:         resolverTo(newFakeDNS(t, fakeDNSEmpty)),
		fallbackResolver: nil,
		option:           Option{CacheTTL: time.Minute},
		dnsCache:         map[string]*dnsCacheEntry{},
	})

	if _, err := ResolveIPAddrs("node.example.com"); err == nil {
		t.Fatal("expected an error when the resolver answers without an address")
	}
}

func TestResolveAppliesDeadline(t *testing.T) {
	oldTimeout := resolveAddrTimeout
	resolveAddrTimeout = 100 * time.Millisecond
	t.Cleanup(func() { resolveAddrTimeout = oldTimeout })

	// Both legs are blackholed, so only the deadline can end the lookup.
	withDirect(t, &directDialer{
		resolver:         resolverTo(newFakeDNS(t, fakeDNSBlackhole)),
		fallbackResolver: resolverTo(newFakeDNS(t, fakeDNSBlackhole)),
		option:           Option{CacheTTL: time.Minute},
		dnsCache:         map[string]*dnsCacheEntry{},
	})

	start := time.Now()
	_, err := ResolveIPAddrs("node.example.com")
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("expected the lookup to stop at its budget, took %v", elapsed)
	}
}

// TestResolveContextIsAlsoBounded covers the context-carrying variant: a caller
// whose context has no deadline still gets the internal cap.
func TestResolveContextIsAlsoBounded(t *testing.T) {
	oldTimeout := resolveAddrTimeout
	resolveAddrTimeout = 100 * time.Millisecond
	t.Cleanup(func() { resolveAddrTimeout = oldTimeout })

	withDirect(t, &directDialer{
		resolver:         resolverTo(newFakeDNS(t, fakeDNSBlackhole)),
		fallbackResolver: resolverTo(newFakeDNS(t, fakeDNSBlackhole)),
		option:           Option{CacheTTL: time.Minute},
		dnsCache:         map[string]*dnsCacheEntry{},
	})

	done := make(chan error, 1)
	go func() {
		_, err := ResolveIPAddrsContext(context.Background(), "node.example.com")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ResolveIPAddrsContext did not honour its internal budget")
	}
}

func TestResolveUDPAddrsRejectsBadPort(t *testing.T) {
	withDirect(t, foreignDialer{})

	if _, err := ResolveUDPAddrs("node.example.com:not-a-port"); err == nil {
		t.Fatal("expected an error for a malformed port")
	}
	if _, err := ResolveUDPAddrs("node.example.com"); err == nil {
		t.Fatal("expected an error for a missing port")
	}
}

// TestResolveLegBoundCoversDeadlineLessCallers pins the per-leg bound: a caller
// with no deadline and two blackholed legs must get a failure at the leg budget
// instead of hanging on the resolvers' internal retry loops. The joined error
// keeps leg order. (Port of kdae 007cdbd8.)
func TestResolveLegBoundCoversDeadlineLessCallers(t *testing.T) {
	oldLeg := resolveLegTimeout
	resolveLegTimeout = 150 * time.Millisecond
	t.Cleanup(func() { resolveLegTimeout = oldLeg })

	withDirect(t, &directDialer{
		resolver:         resolverTo(newFakeDNS(t, fakeDNSBlackhole)),
		fallbackResolver: resolverTo(newFakeDNS(t, fakeDNSBlackhole)),
		option:           Option{CacheTTL: time.Minute},
		dnsCache:         map[string]*dnsCacheEntry{},
	})

	start := time.Now()
	_, err := ResolveHost(context.Background(), "node.example.com")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an error from two blackholed legs")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded from the leg bounds, got %v", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("expected the legs to stop at their own budget, took %v", elapsed)
	}
}
