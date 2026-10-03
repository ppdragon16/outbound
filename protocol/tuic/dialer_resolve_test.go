package tuic

import (
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	utls "github.com/refraction-networking/utls"
)

// foreignDialer is not a *directDialer, so direct.ResolveHost rejects it. It
// makes "did the server address go through the direct policy?" observable
// without touching DNS.
type foreignDialer struct{ netproxy.Dialer }

// TestNewDialerResolvesProxyAddressThroughDirectPolicy pins the node-address
// resolution: a QUIC transport targets addresses, so this dialer resolves the
// server itself, and that lookup must use the same policy a dial would.
func TestNewDialerResolvesProxyAddressThroughDirectPolicy(t *testing.T) {
	old := direct.Direct
	direct.Direct = foreignDialer{}
	t.Cleanup(func() { direct.Direct = old })

	header := protocol.Header{
		ProxyAddress: "node.example.com:10383",
		TlsConfig:    &utls.Config{ServerName: "node.example.com"},
		User:         "00000000-0000-0000-0000-000000000000",
		Password:     "password",
	}

	_, err := NewDialer(direct.Direct, header)
	if err == nil {
		t.Fatal("expected the hostname to be resolved through the direct policy")
	}
	if !strings.Contains(err.Error(), "not a direct dialer") {
		t.Fatalf("expected the direct policy's error, got %v", err)
	}
}

// TestNewDialerAcceptsLiteralProxyAddress covers the no-DNS configuration: a
// literal address must not consult the policy at all.
func TestNewDialerAcceptsLiteralProxyAddress(t *testing.T) {
	old := direct.Direct
	direct.Direct = foreignDialer{}
	t.Cleanup(func() { direct.Direct = old })

	header := protocol.Header{
		ProxyAddress: "127.0.0.1:10383",
		TlsConfig:    &utls.Config{ServerName: "node.example.com"},
		User:         "00000000-0000-0000-0000-000000000000",
		Password:     "password",
	}

	if _, err := NewDialer(direct.Direct, header); err != nil {
		t.Fatalf("expected a literal address to build the dialer, got %v", err)
	}
}
