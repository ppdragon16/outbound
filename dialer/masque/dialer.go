// Package masque exposes the MASQUE proxy client (RFC 9298 CONNECT-UDP over
// HTTP/3 + QUIC datagrams) as a netproxy.Dialer. TCP is tunneled via plain
// HTTP/3 CONNECT, UDP via per-target CONNECT-UDP streams.
package masque

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	masque "github.com/daeuniverse/outbound/protocol/masque"
)

// Dialer tunnels traffic through a MASQUE proxy. TCP rides plain HTTP/3
// CONNECT streams; UDP rides per-target CONNECT-UDP streams (RFC 9298) with
// HTTP datagrams (RFC 9297).
type Dialer struct {
	protocol.StatelessDialer
	addr          string
	sni           string
	allowInsecure bool

	mu  sync.Mutex
	ins *masque.Client
}

// NewDialer returns a MASQUE dialer. sni is the TLS SNI (empty = proxy
// host); allowInsecure skips certificate verification.
func NewDialer(parent netproxy.Dialer, addr, sni string, allowInsecure bool) (*Dialer, error) {
	if addr == "" {
		return nil, fmt.Errorf("masque: proxy address is required")
	}
	return &Dialer{
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: parent,
		},
		addr:          addr,
		sni:           sni,
		allowInsecure: allowInsecure,
	}, nil
}

// client lazily builds the shared MASQUE client (one H3 connection).
func (d *Dialer) client() (*masque.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ins != nil {
		return d.ins, nil
	}
	c, err := masque.NewClient(d.addr, d.sni, d.allowInsecure)
	if err != nil {
		return nil, err
	}
	d.ins = c
	return c, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("%w: masque+%v", netproxy.UnsupportedTunnelTypeError, network)
	}
	client, err := d.client()
	if err != nil {
		return nil, err
	}
	return client.DialContext(ctx, "tcp", address)
}

func (d *Dialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	client, err := d.client()
	if err != nil {
		return nil, err
	}
	return client.ListenPacket(ctx)
}
