package trojanc

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	protocol.Register("trojanc", NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
	password     string
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	//log.Trace("trojanc.NewDialer: metadata: %v, password: %v", metadata, password)
	return &Dialer{
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		metadata:     metadata,
		password:     header.Password,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.IsClient = d.metadata.IsClient

		conn, err := d.nextDialer.DialContext(ctx, "tcp", d.proxyAddress)
		if err != nil {
			return nil, err
		}

		tcpConn, err := NewConn(conn, Metadata{
			Metadata: mdata,
			Network:  "tcp",
		}, d.password)
		if err != nil {
			return nil, err
		}
		if network == "tcp" {
			return tcpConn, nil
		} else {
			return &PacketConn{Conn: tcpConn}, nil
		}
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return nil, err
	}
	mdata.IsClient = d.metadata.IsClient

	conn, err := d.nextDialer.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, err
	}

	tcpConn, err := NewConn(conn, Metadata{
		Metadata: mdata,
		Network:  "tcp",
	}, d.password)
	if err != nil {
		return nil, err
	}
	return &PacketConn{Conn: tcpConn}, nil
}
