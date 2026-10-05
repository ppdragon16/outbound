package trojanc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

// streamStubConn serves a canned byte stream; ReadFrom only ever calls Read on
// the conn (io.ReadFull / io.CopyN), so the embedded nil interface covers the
// rest of net.Conn.
type streamStubConn struct {
	net.Conn
	r io.Reader
}

func (c *streamStubConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// trojanFrame builds one datagram frame: ATYP + IPv4 addr + port + len + CRLF +
// payload.
func trojanFrame(payload []byte) []byte {
	out := []byte{0x01, 1, 2, 3, 4, 0, 30, 0, 0} // ATYP + addr + port + len
	binary.BigEndian.PutUint16(out[7:9], uint16(len(payload)))
	out = append(out, 0x0d, 0x0a)
	return append(out, payload...)
}

// TestReadFromDropsOversizedPayloadAndKeepsStreamAligned pins the read-side
// datagram-dropped contract: a datagram larger than the caller's buffer is
// drained from the stream and reported through the contract, and the NEXT
// datagram is still parseable -- before the drain, the payload stayed in the
// stream and every later read desynchronized. (Port of olicesx/outbound
// 7f939b6's read-side contract.)
func TestReadFromDropsOversizedPayloadAndKeepsStreamAligned(t *testing.T) {
	big := bytes.Repeat([]byte{0x11}, 500)
	stream := append(trojanFrame(big), trojanFrame([]byte("OK"))...)
	c := &PacketConn{Conn: &streamStubConn{r: bytes.NewReader(stream)}}

	small := make([]byte, 64)
	_, _, err := c.ReadFrom(small)
	if err == nil {
		t.Fatal("expected the oversized datagram to be rejected")
	}
	var dropped *netproxy.ErrDatagramDropped
	if !errors.As(err, &dropped) {
		t.Fatalf("err = %v, want the datagram-dropped contract", err)
	}
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("err = %v, want io.ErrShortBuffer as the legacy cause", err)
	}

	n, addr, err := c.ReadFrom(small)
	if err != nil {
		t.Fatalf("ReadFrom after the drop: %v", err)
	}
	if string(small[:n]) != "OK" {
		t.Fatalf("payload = %q, want OK", small[:n])
	}
	if addr.String() != "1.2.3.4:30" {
		t.Fatalf("addr = %v, want 1.2.3.4:30", addr)
	}
}
