package coalesce

import "net"

// FlushConn is the wrapper a transport returns to its protocol layer: every
// Write returns only after the coalesced records of that write burst have
// been pushed to the socket, so plain Write/Read users need no flush
// discipline of their own. Reads pass straight through to the embedded
// conn, whose coalescer flushes before blocking.
type FlushConn struct {
	net.Conn
	co *Conn
}

// NewFlushConn wraps an established TLS-layer conn and binds it to the
// coalescer sitting underneath that TLS layer.
func NewFlushConn(conn net.Conn, co *Conn) *FlushConn {
	return &FlushConn{Conn: conn, co: co}
}

func (f *FlushConn) Write(b []byte) (int, error) {
	n, err := f.Conn.Write(b)
	if ferr := f.co.Flush(); ferr != nil && err == nil {
		err = ferr
	}
	return n, err
}

// compile-time interface check.
var _ net.Conn = (*FlushConn)(nil)
