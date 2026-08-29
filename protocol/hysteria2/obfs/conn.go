/*
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Per-packet obfuscation wrapper for net.PacketConn, ported from
 * github.com/apernet/hysteria (extras/obfs/conn.go), AGPL-3.0.
 */

package obfs

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

const udpBufferSize = 2048 // QUIC packets are at most 1500 bytes long, so 2k should be more than enough

// obfuscator wraps a per-packet, length-preserving cipher.
// Obfuscate / Deobfuscate return the number of bytes written to out.
// If a packet is not valid, the methods should return 0.
type obfuscator interface {
	Obfuscate(in, out []byte) int
	Deobfuscate(in, out []byte) int
}

var _ net.PacketConn = (*obfsPacketConn)(nil)

type obfsPacketConn struct {
	Conn net.PacketConn
	Obfs obfuscator

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

// udpLikePacketConn is the subset of *net.UDPConn methods that quic-go relies
// on for UDP-specific optimizations (DF/PMTU detection and recv/send buffer
// sizing). Anything that satisfies this interface — including a wrapper — will
// keep those optimizations when wrapped in obfs.
type udpLikePacketConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

// obfsPacketConnUDP is a special case of obfsPacketConn that wraps a
// UDP-flavored PacketConn. We pass additional methods through to quic-go to
// enable UDP-specific optimizations.
type obfsPacketConnUDP struct {
	*obfsPacketConn
	UDPConn udpLikePacketConn
}

// wrapPacketConn enables per-packet obfuscation on a net.PacketConn.
// The obfuscation is transparent to the caller - the n bytes returned by
// ReadFrom and WriteTo are the number of original bytes, not after
// obfuscation/deobfuscation.
func wrapPacketConn(conn net.PacketConn, ob obfuscator) net.PacketConn {
	opc := &obfsPacketConn{
		Conn:     conn,
		Obfs:     ob,
		readBuf:  make([]byte, udpBufferSize),
		writeBuf: make([]byte, udpBufferSize),
	}
	if udpConn, ok := conn.(udpLikePacketConn); ok {
		return &obfsPacketConnUDP{
			obfsPacketConn: opc,
			UDPConn:        udpConn,
		}
	} else {
		return opc
	}
}

func (c *obfsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		c.readMutex.Lock()
		n, addr, err = c.Conn.ReadFrom(c.readBuf)
		if n <= 0 {
			c.readMutex.Unlock()
			return n, addr, err
		}
		n = c.Obfs.Deobfuscate(c.readBuf[:n], p)
		c.readMutex.Unlock()
		if n > 0 || err != nil {
			return n, addr, err
		}
		// Invalid packet, try again
	}
}

// ReadFromAddrPort forwards the quic-go fork's allocation-free read fast path
// through the obfuscation layer; without this forward the type assertion on
// the wrapper would fail and quic-go would fall back to the ReadFrom path.
// The returned addr must be valid on success — quic-go treats an invalid one
// as "fast path unsupported" and re-reads the socket via ReadFrom, silently
// dropping the packet.
func (c *obfsPacketConnUDP) ReadFromAddrPort(p []byte) (n int, addr netip.AddrPort, err error) {
	apc, ok := c.Conn.(interface {
		ReadFromAddrPort([]byte) (int, netip.AddrPort, error)
	})
	if !ok {
		// Inner conn has no fast path; degrade to ReadFrom and convert.
		// Fail fast on unconvertible addresses: returning n>0 with an
		// invalid AddrPort would make quic-go drop the packet and re-read
		// the socket via ReadFrom.
		nn, a, rerr := c.ReadFrom(p)
		if rerr != nil {
			return 0, netip.AddrPort{}, rerr
		}
		ua, ok := a.(*net.UDPAddr)
		if !ok {
			return 0, netip.AddrPort{}, errors.New("obfs: inner conn returned a non-UDPAddr address")
		}
		return nn, ua.AddrPort(), nil
	}
	for {
		c.readMutex.Lock()
		nn, ap, rerr := apc.ReadFromAddrPort(c.readBuf)
		if nn <= 0 {
			c.readMutex.Unlock()
			return nn, ap, rerr
		}
		n = c.Obfs.Deobfuscate(c.readBuf[:nn], p)
		c.readMutex.Unlock()
		if n > 0 || rerr != nil {
			return n, ap, rerr
		}
		// Invalid packet, try again
	}
}

func (c *obfsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.writeMutex.Lock()
	nn := c.Obfs.Obfuscate(p, c.writeBuf)
	_, err = c.Conn.WriteTo(c.writeBuf[:nn], addr)
	c.writeMutex.Unlock()
	if err == nil {
		n = len(p)
	}
	return n, err
}

// WriteToAddrPort forwards the AddrPort-flavored write through the obfuscation
// layer so wrapper-wrapped conns satisfy the full PacketConnAddrPort shape.
func (c *obfsPacketConnUDP) WriteToAddrPort(p []byte, addr netip.AddrPort) (n int, err error) {
	if apc, ok := c.Conn.(interface {
		WriteToAddrPort([]byte, netip.AddrPort) (int, error)
	}); ok {
		c.writeMutex.Lock()
		nn := c.Obfs.Obfuscate(p, c.writeBuf)
		_, err = apc.WriteToAddrPort(c.writeBuf[:nn], addr)
		c.writeMutex.Unlock()
		if err == nil {
			n = len(p)
		}
		return n, err
	}
	// Inner conn has no fast path; degrade to the net.Addr write.
	return c.WriteTo(p, net.UDPAddrFromAddrPort(addr))
}

func (c *obfsPacketConn) Close() error {
	return c.Conn.Close()
}

func (c *obfsPacketConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *obfsPacketConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *obfsPacketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *obfsPacketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// UDP-specific methods below

func (c *obfsPacketConnUDP) SetReadBuffer(bytes int) error {
	return c.UDPConn.SetReadBuffer(bytes)
}

func (c *obfsPacketConnUDP) SetWriteBuffer(bytes int) error {
	return c.UDPConn.SetWriteBuffer(bytes)
}

func (c *obfsPacketConnUDP) SyscallConn() (syscall.RawConn, error) {
	return c.UDPConn.SyscallConn()
}
