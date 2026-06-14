package vless

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/vless/vision"
	"github.com/daeuniverse/outbound/protocol/vmess"
)

const (
	XRV = "xtls-rprx-vision"
)

func init() {
	protocol.Register("vless", NewDialer)
}

type Dialer struct {
	protocol.StatelessDialer
	proxyAddress string
	nextDialer   netproxy.Dialer
	flow         string
	xudp         bool
	tcpMux       bool
	key          []byte
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	id, err := Password2Key(header.Password)
	if err != nil {
		return nil, err
	}

	var flowStr string
	if header.Feature1 != nil {
		var ok bool
		flowStr, ok = header.Feature1.(string)
		if !ok {
			return nil, fmt.Errorf("Feature1 must be a string, got %T", header.Feature1)
		}
	}

	switch flowStr {
	case XRV:
	case "":
	default:
		return nil, fmt.Errorf("unsupported xtls flow type: %v", flowStr)
	}

	return &Dialer{
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: nextDialer,
		},
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		flow:         flowStr,
		xudp:         flowStr == XRV,
		tcpMux:       header.Flags&protocol.Flags_VLess_TcpMux != 0,
		key:          id,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.IsClient = true

		conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
		if err != nil {
			return nil, fmt.Errorf("dial proxy: %w", err)
		}

		conn, err = NewConn(conn, Metadata{
			Metadata: vmess.Metadata{
				Metadata: mdata,
				Network:  network,
			},
			Flow: d.flow,
			Mux:  (network == "udp" && d.xudp) || (d.tcpMux && network == "tcp"),
		}, d.key)
		if err != nil {
			conn.Close()
			return nil, err
		}

		if d.flow == XRV {
			if d.xudp {
				pc, err := vision.NewPacketConn(conn, d.key, network, addr)
				if err != nil {
					conn.Close()
					return nil, err
				}
				return pc, nil
			}
			vc, err := vision.NewConn(conn, d.key)
			if err != nil {
				conn.Close()
				return nil, err
			}
			return vc, nil
		}

		if network == "udp" {
			return &netproxy.BindPacketConn{
				PacketConn: conn.(net.PacketConn),
				Address:    netproxy.NewAddr("udp", addr),
			}, nil
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return nil, err
	}
	mdata.IsClient = true

	conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}

	vConn, err := NewConn(conn, Metadata{
		Metadata: vmess.Metadata{
			Metadata: mdata,
			Network:  "udp",
		},
		Flow: d.flow,
		Mux:  d.xudp,
	}, d.key)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if d.flow == XRV {
		pc, err := vision.NewPacketConn(vConn, d.key, "udp", addr)
		if err != nil {
			vConn.Close()
			return nil, err
		}
		return pc, nil
	}
	return vConn, nil
}
