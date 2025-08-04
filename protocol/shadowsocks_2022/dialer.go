package shadowsocks_2022

import (
	"context"
	"crypto/cipher"
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
)

func init() {
	protocol.Register("shadowsocks_2022", NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	conf         *ciphers.CipherConf2022
	key          []byte
	sg           shadowsocks.SaltGenerator
	blockCipher  cipher.Block
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	conf := ciphers.Aead2022CiphersConf[header.Cipher]
	key, err := ciphers.ValidateBase64PSK(header.Password, conf.KeyLen)
	if err != nil {
		return nil, err
	}
	sg, err := shadowsocks.NewSaltGenerator(key, conf.SaltLen)
	if err != nil {
		return nil, err
	}
	blockCipher, err := conf.NewBlockCipher(key)
	if err != nil {
		return nil, err
	}
	return &Dialer{
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		conf:         conf,
		key:          key,
		sg:           sg,
		blockCipher:  blockCipher,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp":
		addrInfo, err := shadowsocks.AddressFromString(addr)
		if err != nil {
			return nil, err
		}
		// Shadowsocks transfer TCP traffic via TCP tunnel.
		conn, err := d.nextDialer.DialContext(ctx, network, d.proxyAddress)
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
			Address:    netproxy.NewProxyAddr("udp", addr),
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	// TODO: 这里不应该基于addr做决断

	// Shadowsocks transfer UDP traffic via UDP tunnel.
	conn, err := d.nextDialer.DialContext(ctx, "udp", d.proxyAddress)
	if err != nil {
		return nil, err
	}
	return NewUdpConn(conn, d.conf, d.blockCipher, d.key, nil)
}
