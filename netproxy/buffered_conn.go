package netproxy

import (
	"bufio"
	"net"
)

// BufferedConn serves Read from a bufio.Reader that already consumed part of
// the stream -- a protocol handshake -- so the bytes that reader pulled past
// the handshake are not lost when the session switches to the connection. A
// handshake read fills the reader's whole window, so a peer that speaks first
// (or plain TCP coalescing) can put payload into it: returning the raw conn
// would drop those bytes and desynchronize the session.
type BufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *BufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// NewBufferedConn returns conn reading through r.
//
// A conn that supports a half-close keeps that capability: the wrapper composes
// CloseWriteConn rather than defining CloseWrite itself. A wrapper that answers
// CloseWrite for an inner conn that cannot half-close would make the relay
// believe the peer received its FIN, so the capability must stay fail-closed.
func NewBufferedConn(conn net.Conn, r *bufio.Reader) net.Conn {
	bc := &BufferedConn{Conn: conn, r: r}
	if cw, ok := conn.(CloseWriter); ok {
		return &CloseWriteConn{Conn: bc, CloseWriter: cw}
	}
	return bc
}
