package smux

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/xtaci/smux"
)

const (
	ProtocolSmux = iota
	ProtocolYAMux
	ProtocolH2Mux
)

const (
	Version0 = iota
	Version1
)

const (
	flagUDP       = 0b01
	flagAddr      = 0b10
	statusSuccess = 0
	statusError   = 1
)

type Smux struct {
	Dialer         netproxy.Dialer
	PassthroughUdp bool

	session *smux.Session
}

type SmuxConfig struct {
	PassThroughUDP bool
}

func (s *SmuxConfig) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, error) {
	return &Smux{
		Dialer:         nextDialer,
		PassthroughUdp: s.PassThroughUDP,
	}, nil
}

func (s *Smux) Connect() (err error) {
	ctx, cancel := netproxy.NewDialTimeoutContext()
	defer cancel()
	conn, err := s.Dialer.DialContext(ctx, "tcp", "sp.mux.sing-box.arpa:444")
	if err != nil {
		return err
	}
	_, err = common.Invoke(ctx, func() (any, error) {
		return conn.Write([]byte{Version0, ProtocolSmux})
	}, func() {
		conn.Close()
	})
	if err != nil {
		return
	}
	s.session, _ = smux.Client(conn, nil)
	return
}

func (s *Smux) Alive() bool {
	if s.Dialer.Alive() {
		return s.session != nil && !s.session.IsClosed()
	}
	return false
}

func (s *Smux) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp":
		stream, err := s.session.OpenStream()
		if err != nil {
			return nil, err
		}
		return &Conn{Conn: stream, addr: addr}, nil
	case "udp":
		conn, err := s.ListenPacket(ctx, addr)
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

func (s *Smux) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	stream, err := s.session.OpenStream()
	if err != nil {
		return nil, err
	}
	return &UDPConn{Conn: Conn{Conn: stream, addr: addr, udp: true, packetAddr: true}}, nil
}
