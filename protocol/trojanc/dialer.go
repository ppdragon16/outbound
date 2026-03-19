package trojanc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	// Pre-computed hex-encoded SHA224 hash (56 bytes)
	hexPassword []byte
}

func NewDialer(parentDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	// Pre-calculate Trojan password hash (SHA224 hex string)
	// Trojan standard uses sha224(password) -> hex string
	h := sha256.New224()
	h.Write([]byte(header.Password))
	passHash := hex.EncodeToString(h.Sum(nil))

	return &Dialer{
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: parentDialer,
		},
		proxyAddress: header.ProxyAddress,
		hexPassword:  []byte(passHash), // Store as []byte to avoid string-to-slice conversion later
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "udp":
		// 1. Prepare address metadata
		addressInfo, err := socks5.AddressFromString(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse address: %w", err)
		}

		// 2. Dial the proxy server (usually TLS over TCP)
		conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to proxy: %w", err)
		}

		// 3. Wrap with Trojan protocol.
		// Note: Pass hexPassword directly to avoid re-hashing.
		tcpConn := NewConn(conn, addressInfo, network, d.hexPassword)

		if network == "udp" {
			return &netproxy.BindPacketConn{
				PacketConn: &PacketConn{Conn: tcpConn},
				Address:    netproxy.NewAddr("udp", addr),
			}, nil
		}
		return tcpConn, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	// Reuse logic: Dialing UDP in Trojan is just a TCP connection with UDP command.
	// Most Trojan implementations use a zero/fake address for ListenPacket
	// until the first WriteTo is called, but following your existing logic:
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}

	// If DialContext returns net.Conn, we need the underlying PacketConn for ListenPacket interface
	if pc, ok := conn.(net.PacketConn); ok {
		return pc, nil
	}

	// Fallback/Safety wrapper
	return &PacketConn{Conn: conn}, nil
}
