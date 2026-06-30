package shadowsocks_stream

import (
	"net/netip"
	"time"
)

// PacketConn is a generic packet-oriented connection interface used by SSR protocols.
// It differs from net.PacketConn by using netip.AddrPort in ReadFrom
// and accepting a string address in WriteTo.
type PacketConn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	ReadFrom(p []byte) (n int, addr netip.AddrPort, err error)
	WriteTo(p []byte, addr string) (n int, err error)
	Close() error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}
