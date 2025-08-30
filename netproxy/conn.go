package netproxy

import (
	"net"
)

var UnsupportedTunnelTypeError = net.UnknownNetworkError("unsupported tunnel type")

type CloseWriter interface {
	CloseWrite() error
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
