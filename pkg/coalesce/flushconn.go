package coalesce

import (
	"net"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

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

// CloseWrite forwards half-close and then flushes the coalesced records that
// carried it. crypto/tls.Conn implements CloseWrite, but the promoted method
// set of an embedded net.Conn does not include it, so without this forward
// every TLS-based transport silently lost half-close.
//
// The flush needs its own deadline window: crypto/tls closeNotify bounds the
// alert write with a 5s write deadline and then re-arms the deadline to
// time.Now() so that any subsequent write fails. That assumes c.conn.Write
// delivered the bytes to the socket; the coalescer deferred them, so the
// re-armed deadline would make the flush below drop the close_notify and
// surface i/o timeout on every half-close. Re-arm a fresh 5s window for the
// alert, flush it, then restore the writes-after-CloseWrite-fail contract.
func (f *FlushConn) CloseWrite() error {
	err := netproxy.ForwardCloseWrite(f.Conn)
	ferr := f.co.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if ferr == nil {
		ferr = f.co.Flush()
	}
	// tls.Conn.CloseWrite leaves the write deadline in the past on purpose:
	// any write after the half-close must fail. Keep that contract.
	_ = f.co.SetWriteDeadline(time.Now())
	if err == nil {
		err = ferr
	}
	return err
}

// compile-time interface check.
var _ net.Conn = (*FlushConn)(nil)
