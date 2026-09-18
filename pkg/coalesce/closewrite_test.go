package coalesce

import (
	"net"
	"testing"
	"time"
)

// tlsLikeConn mimics crypto/tls.Conn's CloseWrite deadline behaviour: it
// bounds the alert write with a 5s write deadline and then re-arms the
// underlying deadline to time.Now() so any subsequent write fails. A
// coalescer underneath defers the bytes, so without the FlushConn.CloseWrite
// deadline re-arm the close_notify would be dropped with i/o timeout.
type tlsLikeConn struct {
	net.Conn
	closeWriteErr error
}

func (c *tlsLikeConn) CloseWrite() error {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, werr := c.Conn.Write([]byte("close_notify"))
	c.closeWriteErr = werr
	// The poison: subsequent writes must fail.
	_ = c.Conn.SetWriteDeadline(time.Now())
	return werr
}

// halfCloseConn records a CloseWrite call and never blocks writes.
type halfCloseConn struct {
	net.Conn
	halfClosed bool
	writes     [][]byte
}

func (c *halfCloseConn) Write(p []byte) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)
	c.writes = append(c.writes, b)
	return len(p), nil
}

func (c *halfCloseConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *halfCloseConn) CloseWrite() error {
	c.halfClosed = true
	return nil
}

// TestFlushConnCloseWriteFlushesPastDeadlinePoisoning verifies the
// close_notify written by the inner TLS layer's CloseWrite reaches the
// socket even though that CloseWrite re-armed the write deadline to the
// past (the coalescer defers the bytes, so the poisoned deadline would
// otherwise drop them with os.ErrDeadlineExceeded).
func TestFlushConnCloseWriteFlushesPastDeadlinePoisoning(t *testing.T) {
	raw := &halfCloseConn{}
	tlsConn := &tlsLikeConn{Conn: raw}
	co := New(raw)
	f := NewFlushConn(tlsConn, co)

	if err := f.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	// tls.Conn semantics: CloseWrite sends only the close_notify alert; the
	// FIN comes with Close. What must hold here is that the alert — buffered
	// by the coalescer while the inner layer poisoned the write deadline —
	// still reached the socket.
	var got []byte
	for _, w := range raw.writes {
		got = append(got, w...)
	}
	if string(got) != "close_notify" {
		t.Fatalf("close_notify lost or duplicated on the socket: %q", got)
	}
}

// TestConnCloseWriteFlushesBeforeFin verifies coalesce.Conn.CloseWrite flushes
// buffered records before half-closing the socket, so the FIN cannot overtake
// its own data.
func TestConnCloseWriteFlushesBeforeFin(t *testing.T) {
	raw := &halfCloseConn{}
	co := New(raw)
	if _, err := co.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if co.Pending() == 0 {
		t.Fatal("expected buffered bytes before CloseWrite")
	}
	if err := co.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if co.Pending() != 0 {
		t.Fatalf("records still buffered after CloseWrite: %d", co.Pending())
	}
	if !raw.halfClosed {
		t.Fatal("half-close was not forwarded to the raw conn")
	}
	if len(raw.writes) == 0 || string(raw.writes[0]) != "payload" {
		t.Fatalf("payload lost or reordered: %v", raw.writes)
	}
}
