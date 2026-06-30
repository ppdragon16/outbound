package obfs

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/shadowsocks_stream"
)

type Dialer struct {
	NextDialer netproxy.Dialer
	param      *ObfsParam

	constructor *constructor
}
type ObfsParam struct {
	ObfsHost  string
	ObfsPort  uint16
	Obfs      string
	ObfsParam string
}

func NewDialer(nextDialer netproxy.Dialer, param *ObfsParam) (*Dialer, error) {

	constructor := NewObfs(param.Obfs)
	if constructor == nil {
		return nil, errors.New("unsupported protocol type: " + param.Obfs)
	}

	d := &Dialer{
		NextDialer:  nextDialer,
		param:       param,
		constructor: constructor,
	}
	return d, nil
}

func (d *Dialer) ObfsOverhead() int {
	return d.constructor.Overhead
}

func (d *Dialer) Alive() bool {
	return d.NextDialer.Alive()
}

func (d *Dialer) Connect() error {
	return d.NextDialer.Connect()
}

func (d *Dialer) Disconnect() error {
	return d.NextDialer.Disconnect()
}

func (d *Dialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return d.NextDialer.ListenPacket(ctx, address)
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	magicNetwork, err := shadowsocks_stream.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		conn, err := d.NextDialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		obfs := d.constructor.New()
		if obfs == nil {
			return nil, errors.New("unsupported protocol type: " + d.param.Obfs)
		}
		obfsServerInfo := &ServerInfo{
			Host:  d.param.ObfsHost,
			Port:  d.param.ObfsPort,
			Param: d.param.ObfsParam,
		}
		obfs.SetData(obfs.GetData())
		obfs.SetServerInfo(obfsServerInfo)

		return NewConn(conn, obfs)
	case "udp":
		return d.NextDialer.DialContext(ctx, network, addr)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
