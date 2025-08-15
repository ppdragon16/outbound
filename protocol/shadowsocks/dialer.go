package shadowsocks

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

func init() {
	protocol.Register("shadowsocks", NewDialer)
}

type Dialer struct {
	protocol.StatelessDialer
	proxyAddress string
	conf         *ciphers.CipherConf
	key          []byte
	sg           SaltGenerator
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	conf := ciphers.AeadCiphersConf[header.Cipher]
	key := common.EVPBytesToKey(header.Password, conf.KeyLen)
	sg, err := NewRandomSaltGenerator(conf.SaltLen)
	if err != nil {
		return nil, err
	}
	//log.Trace("shadowsocks.NewDialer: metadata: %v, password: %v", metadata, password)
	return &Dialer{
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: nextDialer,
		},
		proxyAddress: header.ProxyAddress,
		conf:         conf,
		key:          key,
		sg:           sg,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp":
		addrInfo, err := socks5.AddressFromString(addr)
		if err != nil {
			return nil, err
		}
		// Shadowsocks transfer TCP traffic via TCP tunnel.
		conn, err := d.ParentDialer.DialContext(ctx, network, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		return NewTCPConn(conn, d.conf, d.key, d.sg, addrInfo, nil)
	case "udp":
		conn, err := d.ListenPacket(ctx, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{
			PacketConn: conn,
			Address:    netproxy.NewAddr("udp", addr),
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	// Shadowsocks transfer UDP traffic via UDP tunnel.
	conn, err := d.ParentDialer.DialContext(ctx, "udp", d.proxyAddress)
	if err != nil {
		return nil, err
	}
	return NewUdpConn(conn, d.conf, d.key, d.sg, nil)
}
