package juicity

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/quic-go"
)

func ToAddrPort(addr net.Addr) (netip.AddrPort, error) {
	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.AddrPort(), nil
	case *net.TCPAddr:
		return v.AddrPort(), nil
	default:
		return netip.ParseAddrPort(addr.String())
	}
}

type TransportPacketConn struct {
	*quic.Transport
	proxyAddr *net.UDPAddr
	tgt       netip.AddrPort
	masterKey []byte
	firstIv   []byte
	mu        sync.Mutex
}

// LocalAddr implements net.PacketConn.
func (c *TransportPacketConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// SetDeadline implements net.PacketConn.
func (c *TransportPacketConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline implements net.PacketConn.
func (c *TransportPacketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.PacketConn.
func (c *TransportPacketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func (c *TransportPacketConn) Write(b []byte) (int, error) {
	return c.WriteToAddrPort(b, c.tgt)
}

func (c *TransportPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

// ReadFrom implements net.PacketConn.
func (c *TransportPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, ap, err := c.ReadFromAddrPort(p)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(ap), nil
}

// WriteTo implements net.PacketConn.
func (c *TransportPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	ap, err := ToAddrPort(addr)
	if err != nil {
		return 0, err
	}
	return c.WriteToAddrPort(p, ap)
}

// ReadFromAddrPort reads a packet and returns the source address as netip.AddrPort.
func (c *TransportPacketConn) ReadFromAddrPort(p []byte) (n int, ap netip.AddrPort, err error) {
	buf := pool.GetBuffer(len(p) + CipherConf.SaltLen + CipherConf.TagLen)
	defer pool.PutBuffer(buf)
	n, _, err = c.Transport.ReadNonQUICPacket(context.TODO(), buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	plain, err := decryptJuicityUDP(c.masterKey, buf[:n], CipherConf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	n = copy(p, plain)
	return n, c.tgt, nil
}

// WriteToAddrPort writes a packet to the target address.
// Returns plaintext length as required by the io.Writer/PacketConn contract.
func (c *TransportPacketConn) WriteToAddrPort(b []byte, ap netip.AddrPort) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var salt []byte
	if c.firstIv != nil {
		salt = c.firstIv
		c.firstIv = nil
	} else {
		salt = pool.GetBuffer(CipherConf.SaltLen)
		defer pool.PutBuffer(salt)
		salt[0] = 0
		salt[1] = 0
		fastrand.Read(salt[2:])
	}
	toWrite, err := encryptJuicityUDP(c.masterKey, b, salt, CipherConf)
	if err != nil {
		return 0, err
	}
	defer pool.PutBuffer(toWrite)
	wn, err := c.Transport.WriteTo(toWrite, c.proxyAddr)
	if err != nil {
		return 0, err
	}
	if wn != len(toWrite) {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}

// Close closes both the Transport and the underlying Conn so no resources leak.
// Closing only Conn leaves the Transport's goroutines and connection state alive.
func (c *TransportPacketConn) Close() error {
	var err error
	if c.Transport != nil {
		err = c.Transport.Close()
	}
	if c.Conn != nil {
		if closeErr := c.Conn.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}
