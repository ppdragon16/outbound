package masque

import (
	"context"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
)

// resolveTestDialer is not a *directDialer, so direct.ResolveHost rejects it.
// It makes "did the proxy address go through the direct policy?" observable
// without touching DNS.
type resolveTestDialer struct{ netproxy.Dialer }

// TestEnsureConnResolvesProxyThroughDirectPolicy pins the proxy-address
// resolution: quic.DialAddr would resolve it with the plain system resolver, so
// the client resolves it through the dae policy first and hands quic-go an
// address.
func TestEnsureConnResolvesProxyThroughDirectPolicy(t *testing.T) {
	old := direct.Direct
	direct.Direct = resolveTestDialer{}
	t.Cleanup(func() { direct.Direct = old })

	c, err := NewClient("node.example.com:443", "node.example.com", false)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	_, err = c.ensureConn(context.Background())
	if err == nil {
		t.Fatal("expected the proxy hostname to be resolved through the direct policy")
	}
	if !strings.Contains(err.Error(), "resolve proxy") || !strings.Contains(err.Error(), "not a direct dialer") {
		t.Fatalf("expected a resolve-proxy failure from the direct policy, got %v", err)
	}
}

// TestEnsureConnAcceptsLiteralProxy covers the no-DNS configuration: a literal
// address must not consult the policy, so the failure here is the connection
// attempt and not a resolution error.
func TestEnsureConnAcceptsLiteralProxy(t *testing.T) {
	old := direct.Direct
	direct.Direct = resolveTestDialer{}
	t.Cleanup(func() { direct.Direct = old })

	c, err := NewClient("127.0.0.1:1", "127.0.0.1", true)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A canceled context must fail at the dial, never at the literal's
	// (nonexistent) resolution.
	if _, err := c.ensureConn(ctx); err != nil && strings.Contains(err.Error(), "resolve proxy") {
		t.Fatalf("a literal address must not be resolved, got %v", err)
	}
}
