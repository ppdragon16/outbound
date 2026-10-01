package vision

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

type bufferConn struct {
	*bytes.Buffer
}

func (c *bufferConn) Close() error                     { return nil }
func (c *bufferConn) LocalAddr() net.Addr              { return nil }
func (c *bufferConn) RemoteAddr() net.Addr             { return nil }
func (c *bufferConn) SetDeadline(time.Time) error      { return nil }
func (c *bufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufferConn) SetWriteDeadline(time.Time) error { return nil }

// frameVisionUDPDatagram builds the direct-read vision frame that carries one
// UDP datagram: [frame length][4-byte frame header][command][packet addr]
// [payload length][payload].
func frameVisionUDPDatagram(t *testing.T, addr netip.AddrPort, payload []byte) []byte {
	t.Helper()
	packetAddrLen := IPAddrToPacketAddrLength(addr)
	headerLen := 4 + 1 + packetAddrLen
	var framed bytes.Buffer
	var fl [2]byte
	binary.BigEndian.PutUint16(fl[:], uint16(headerLen))
	framed.Write(fl[:])
	framed.Write([]byte{0, 0, 0x02, 0x01})
	framed.WriteByte(2)
	addrBytes := make([]byte, packetAddrLen)
	if err := PutPacketAddr(addrBytes, addr); err != nil {
		t.Fatal(err)
	}
	framed.Write(addrBytes)
	var ll [2]byte
	binary.BigEndian.PutUint16(ll[:], uint16(len(payload)))
	framed.Write(ll[:])
	framed.Write(payload)
	return framed.Bytes()
}

// newVisionPacketConn wires a vision PacketConn over the given raw stream in
// direct-read mode: no handshake, and every read comes straight from the
// underlay, which is exactly the state after a vision handshake.
func newVisionPacketConn(framed []byte) (*PacketConn, *bufferConn) {
	underlay := &bufferConn{Buffer: bytes.NewBuffer(framed)}
	vc := &Conn{Conn: underlay, toReadDirect: true}
	vc.reader = &readWrapper{directRead: true, vision: vc}
	return &PacketConn{Conn: vc, network: "udp"}, underlay
}

// TestReadFromAcceptsDatagramWithFullRangeBuffer pins the buffer arithmetic of
// the vision UDP read path. dae sizes its DNS forward read buffer with the
// pool's largest bucket (65536 bytes), so len(p) reaches 65536 and a uint16
// cast wraps it to 0: every non-empty datagram then looks oversized, is
// drained and dropped, and all UDP (DNS in particular) over an XTLS/Vision
// node with xudp fails.
func TestReadFromAcceptsDatagramWithFullRangeBuffer(t *testing.T) {
	addr := netip.MustParseAddrPort("203.0.113.10:53")
	payload := bytes.Repeat([]byte{0xAB}, 100)
	for _, bufLen := range []int{1500, 65535, 65536} {
		pc, _ := newVisionPacketConn(frameVisionUDPDatagram(t, addr, payload))
		buf := make([]byte, bufLen)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom with len(p)=%d: err = %v, want nil", bufLen, err)
		}
		if n != len(payload) {
			t.Fatalf("ReadFrom with len(p)=%d: n = %d, want %d", bufLen, n, len(payload))
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("ReadFrom with len(p)=%d: payload mismatch", bufLen)
		}
	}
}

// TestReadFromDrainsOversizedPayload keeps the genuine oversized case working:
// a caller buffer that really is too small must drop that one datagram, leave
// the stream aligned for the next frame, and report a short buffer rather than
// an untyped error or a desynchronized connection.
func TestReadFromDrainsOversizedPayload(t *testing.T) {
	payload := []byte("0123456789")
	addr := netip.MustParseAddrPort("203.0.113.10:53")
	framed := append(frameVisionUDPDatagram(t, addr, payload), "NEXT"...)

	pc, underlay := newVisionPacketConn(framed)
	n, _, err := pc.ReadFrom(make([]byte, 4))
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("ReadFrom err = %v, want io.ErrShortBuffer", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
	rest := make([]byte, 4)
	if _, err := io.ReadFull(underlay, rest); err != nil {
		t.Fatalf("remaining stream: %v", err)
	}
	if string(rest) != "NEXT" {
		t.Fatalf("remaining = %q, want NEXT: the oversized frame was not drained", rest)
	}
}
