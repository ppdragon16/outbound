package netproxy

import (
	"net"
)

var UnsupportedTunnelTypeError = net.UnknownNetworkError("unsupported tunnel type")

type CloseWriter interface {
	CloseWrite() error
}

// ForwardCloseWrite delivers a half-close to the transport that supports it.
// Callers hold a base net.Conn whose static type has no CloseWrite, so
// capability dispatch must go through this helper: wrappers (coalesce
// conns, obfs layers, protocol conns) implement CloseWrite themselves and
// are matched by the assertion below; conns that cannot half-close keep
// the old silent no-op semantics (nil), matching the ok-form call sites.
func ForwardCloseWrite(c net.Conn) error {
	if c == nil {
		return nil
	}
	if wc, ok := c.(CloseWriter); ok {
		return wc.CloseWrite()
	}
	return nil
}

type CloseWriteConn struct {
	net.Conn
	CloseWriter
}

type BindPacketConn struct {
	net.PacketConn
	Address net.Addr
}

func (c *BindPacketConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.Address)
}

func (c *BindPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *BindPacketConn) RemoteAddr() net.Addr {
	return c.Address
}
