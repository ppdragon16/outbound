package shadowtls

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

// Dialer composes a ShadowTLS v3 stream on top of the parent dialer.
// Any net.Conn-speaking outbound (vless, vmess, trojan, ...) can run inside
// it, hence "middle-layer" combinator.
type Dialer struct {
	protocol.StatelessDialer
	addr string
	cfg  Config
}

// NewDialer returns a ShadowTLS dialer wrapping parent.
func NewDialer(parent netproxy.Dialer, addr string, cfg Config) (*Dialer, error) {
	if cfg.Version != 3 {
		return nil, fmt.Errorf("shadow-tls: only protocol version 3 is supported, got %d", cfg.Version)
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("shadow-tls: password is required")
	}
	return &Dialer{
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: parent,
		},
		addr: addr,
		cfg:  cfg,
	}, nil
}

func (s *Dialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("%w: shadow-tls+%v", netproxy.UnsupportedTunnelTypeError, network)
	}
	conn, err := s.ParentDialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	stream, err := NewConn(ctx, conn, s.cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return stream, nil
}

func (s *Dialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return nil, fmt.Errorf("%w: shadow-tls+udp", netproxy.UnsupportedTunnelTypeError)
}
