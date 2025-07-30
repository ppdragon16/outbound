// Modified from https://github.com/nadoo/glider/tree/v0.16.2

package socks5

import (
	"errors"
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/common"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

// PktConn .
type PktConn struct {
	net.PacketConn
	ctrlConn net.Conn // tcp control conn
	server   net.Addr
}

// NewPktConn returns a PktConn, the writeAddr must be *net.UDPAddr or *net.UnixAddr.
func NewPktConn(c net.PacketConn, ctrlConn net.Conn, server net.Addr) *PktConn {
	pc := &PktConn{
		PacketConn: c,
		ctrlConn:   ctrlConn,
		server:     server,
	}

	go func() {
		buf := pool.Get(1)
		defer pool.Put(buf)
		for {
			_, err := ctrlConn.Read(buf)
			if err, ok := err.(net.Error); ok && err.Timeout() {
				continue
			}
			pc.PacketConn.Close()
			// log.F("[socks5] dialudp udp associate end")
			return
		}
	}()

	return pc
}

// ReadFrom overrides the original function from transport.PacketConn.
func (pc *PktConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, from, err := pc.readFrom(b)
	return n, from, err
}

func (pc *PktConn) readFrom(b []byte) (n int, lAddr net.Addr, rAddr net.Addr, err error) {
	buf := pool.Get(len(b))
	defer pool.Put(buf)

	n, rAddr, err = pc.PacketConn.ReadFrom(buf)
	if err != nil {
		return
	}

	if n < 3 {
		return n, rAddr, nil, errors.New("not enough size to get addr")
	}

	// https://www.rfc-editor.org/rfc/rfc1928#section-7
	// +----+------+------+----------+----------+----------+
	// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	// +----+------+------+----------+----------+----------+
	// | 2  |  1   |  1   | Variable |    2     | Variable |
	// +----+------+------+----------+----------+----------+
	tgtAddr := socks.SplitAddr(buf[3:n])
	if tgtAddr == nil {
		return n, rAddr, nil, errors.New("can not get target addr")
	}

	lAddr, err = common.ResolveUDPAddr(tgtAddr.String())
	if err != nil {
		return n, rAddr, nil, errors.New("wrong target addr")
	}

	n = copy(b, buf[3+len(tgtAddr):n])
	return
}

// WriteTo overrides the original function from transport.PacketConn.
func (pc *PktConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	target, err := socks.ParseAddr(addr.String())
	if err != nil {
		return 0, fmt.Errorf("invalid addr: %w", err)
	}

	tgtLen := len(target)
	buf := pool.Get(3 + tgtLen + len(b))
	defer pool.Put(buf)

	copy(buf, []byte{0, 0, 0})
	copy(buf[3:], target)
	copy(buf[3+tgtLen:], b)

	n, err := pc.PacketConn.WriteTo(buf, pc.server)
	if n > tgtLen+3 {
		return n - tgtLen - 3, err
	}

	return 0, err
}

// Close .
func (pc *PktConn) Close() error {
	return errors.Join(pc.ctrlConn.Close(), pc.PacketConn.Close())
}
