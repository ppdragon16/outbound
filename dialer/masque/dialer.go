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
	preferV2      bool
	zeroRTT       bool
	mtu           int

	mu  sync.Mutex
	ins *masque.Client
}

// NewDialer returns a MASQUE dialer. sni is the TLS SNI (empty = proxy
// host); allowInsecure skips certificate verification; preferV2 offers QUIC v2
// (RFC 9369) in the first packet; zeroRTT sends the first request as QUIC 0-RTT
// early data on a resumed session; mtu (0 = safe protocol default) is the QUIC
// Initial packet size, i.e. the path MTU budget.
func NewDialer(parent netproxy.Dialer, addr, sni string, allowInsecure, preferV2, zeroRTT bool, mtu int) (*Dialer, error) {
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
		preferV2:      preferV2,
		zeroRTT:       zeroRTT,
		mtu:           mtu,
	}, nil
}

// client lazily builds the shared MASQUE client (one H3 connection).
func (d *Dialer) client() (*masque.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ins != nil {
		return d.ins, nil
	}
	opts := []masque.Option{masque.WithQuicV2(d.preferV2)}
	if d.zeroRTT {
		opts = append(opts, masque.WithZeroRTT())
	}
	if d.mtu > 0 {
		opts = append(opts, masque.WithMTU(d.mtu))
	}
	c, err := masque.NewClient(d.addr, d.sni, d.allowInsecure, opts...)
	if err != nil {
		return nil, err
	}
	d.ins = c
	return c, nil
}

// DialContext supports both "tcp" (CONNECT tunnel) and "udp" (bound
// CONNECT-UDP packet conn), so connectivity checks and UDP relaying work the
// same way they do for the other QUIC outbounds.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	client, err := d.client()
	if err != nil {
		return nil, err
	}
	switch network {
	case "tcp":
		return client.DialContext(ctx, "tcp", address)
	case "udp":
		pc, err := client.ListenPacket(ctx)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{PacketConn: pc, Address: netproxy.NewAddr("udp", address)}, nil
	default:
		return nil, fmt.Errorf("%w: masque+%v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	client, err := d.client()
	if err != nil {
		return nil, err
	}
	return client.ListenPacket(ctx)
}
