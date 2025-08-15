package trojanc

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

func init() {
	protocol.Register("trojanc", NewDialer)
}

type Dialer struct {
	protocol.StatelessDialer
	proxyAddress string
	password     string
}

func NewDialer(parentDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	return &Dialer{
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: parentDialer,
		},
		proxyAddress: header.ProxyAddress,
		password:     header.Password,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp", "udp":
		// Parse address using shadowsocks implementation
		addressInfo, err := socks5.AddressFromString(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse address: %w", err)
		}

		// Connect to proxy server
		conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to proxy: %w", err)
		}

		// Create Trojan connection
		tcpConn, err := NewConn(conn, addressInfo, network, d.password)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to create Trojan connection: %w", err)
		}

		if network == "tcp" {
			return tcpConn, nil
		} else {
			return &netproxy.BindPacketConn{
				PacketConn: &PacketConn{Conn: tcpConn},
				Address:    netproxy.NewAddr("udp", addr),
			}, nil
		}
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	// Parse address using shadowsocks implementation
	addressInfo, err := socks5.AddressFromString(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse address: %w", err)
	}

	// Connect to proxy server
	conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	// Create Trojan connection for UDP
	tcpConn, err := NewConn(conn, addressInfo, "udp", d.password)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create Trojan UDP connection: %w", err)
	}

	return &PacketConn{Conn: tcpConn}, nil
}
