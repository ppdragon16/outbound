package netproxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

// stubConn is a net.Conn whose Read serves a canned stream; the embedded nil
// interface covers the methods this test does not exercise.
type stubConn struct {
	net.Conn
	r io.Reader
}

func (c *stubConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// closeWriteConn records a forwarded half-close.
type closeWriteConn struct {
	net.Conn
	r         io.Reader
	closeErr  error
	closeCall int
}

func (c *closeWriteConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *closeWriteConn) CloseWrite() error {
	c.closeCall++
	return c.closeErr
}

// TestBufferedConnPreservesBufferedBytes pins the reason the wrapper exists: a
// reader that already pulled payload past the handshake must stay in the read
// path, before the rest of the stream.
func TestBufferedConnPreservesBufferedBytes(t *testing.T) {
	// One live stream: the handshake reads through a bufio window, which fills
	// with the whole segment and leaves the payload buffered while the raw conn
	// itself is drained.
	conn := &stubConn{r: bytes.NewReader([]byte("HANDSHAKEpayload"))}
	stream := bufio.NewReaderSize(conn, 32)
	hs := make([]byte, len("HANDSHAKE"))
	if _, err := io.ReadFull(stream, hs); err != nil {
		t.Fatalf("handshake read: %v", err)
	}

	// The raw conn cannot deliver the buffered payload: this is the loss the
	// wrapper exists to prevent.
	if raw, err := io.ReadAll(conn); err != nil || len(raw) != 0 {
		t.Fatalf("raw conn read %q (err %v), want nothing: the window already consumed it", raw, err)
	}

	wrapped := NewBufferedConn(conn, stream)
	got, err := io.ReadAll(wrapped)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("read %q, want the buffered payload preserved", got)
	}
}

// TestBufferedConnCapabilityStaysFailClosed pins the capability rule: a wrapper
// over a conn that cannot half-close must not expose CloseWrite (a faked
// success would tell the relay the peer got a FIN it never received), while a
// conn that can half-close keeps it and has it forwarded.
func TestBufferedConnCapabilityStaysFailClosed(t *testing.T) {
	plain := NewBufferedConn(&stubConn{r: bytes.NewReader(nil)}, bufio.NewReader(&stubConn{r: bytes.NewReader(nil)}))
	if _, ok := plain.(CloseWriter); ok {
		t.Fatal("a wrapper over a conn without a CloseWriter must not advertise CloseWrite")
	}

	inner := &closeWriteConn{r: bytes.NewReader(nil)}
	wrapped := NewBufferedConn(inner, bufio.NewReader(inner))
	cw, ok := wrapped.(CloseWriter)
	if !ok {
		t.Fatal("a wrapper over a CloseWriter must keep the half-close capability")
	}
	wantErr := errors.New("forwarded")
	inner.closeErr = wantErr
	if err := cw.CloseWrite(); !errors.Is(err, wantErr) {
		t.Fatalf("CloseWrite() = %v, want the inner error", err)
	}
	if inner.closeCall != 1 {
		t.Fatalf("inner CloseWrite called %d times, want 1", inner.closeCall)
	}
}
