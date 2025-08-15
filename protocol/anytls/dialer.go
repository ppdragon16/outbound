package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	protocol.Register("anytls", NewDialer)
}

type Dialer struct {
	protocol.StatelessDialer
	proxyAddress string
	key          []byte
	tlsConfig    *tls.Config

	sessionCounter atomic.Uint64

	idleSessionLock sync.Mutex
	idleSessions    map[uint64]*session
}

func NewDialer(ParentDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	sum := sha256.Sum256([]byte(header.Password))
	return &Dialer{
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: ParentDialer,
		},
		proxyAddress: header.ProxyAddress,
		key:          sum[:],
		tlsConfig:    header.TlsConfig,
		idleSessions: make(map[uint64]*session),
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	switch network {
	case "tcp":
		s, err := d.getSession(ctx)
		if err != nil {
			return nil, err
		}
		return s.newStream(addr)
	case "udp":
		conn, err := d.ListenPacket(ctx, addr)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{
			PacketConn: conn,
			Address:    netproxy.NewAddr(network, addr),
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	s, err := d.getSession(ctx)
	if err != nil {
		return nil, err
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	return s.newPacketStream(net.JoinHostPort("sp.v2.udp-over-tcp.arpa", port), addr)
}

func (d *Dialer) getSession(ctx context.Context) (*session, error) {
	d.idleSessionLock.Lock()
	for seq := range d.idleSessions {
		s := d.idleSessions[seq]
		delete(d.idleSessions, seq)
		if s.closed.Load() {
			continue
		}
		d.idleSessionLock.Unlock()
		return s, nil
	}
	d.idleSessionLock.Unlock()

	conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, d.tlsConfig)

	buf := pool.GetBuffer(len(d.key) + 2)
	defer pool.PutBuffer(buf)
	copy(buf, d.key)
	binary.BigEndian.PutUint16(buf[len(d.key):], uint16(0))
	if _, err := tlsConn.Write(buf); err != nil {
		tlsConn.Close()
		return nil, err
	}

	seq := d.sessionCounter.Add(1)
	s := newSession(tlsConn, seq)
	go func(s *session) {
		for range s.closeStreamChan {
			if s.closed.Load() {
				return
			}
			d.idleSessionLock.Lock()
			if _, ok := d.idleSessions[seq]; !ok {
				d.idleSessions[seq] = s
			}
			d.idleSessionLock.Unlock()
		}
	}(s)

	go s.run()

	return s, nil
}
