package socks5

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

// readStubConn is a net.Conn whose Read serves one canned datagram; only Read
// is reached by the parser, so the embedded nil interface covers the rest.
type readStubConn struct {
	net.Conn
	data []byte
}

func (c *readStubConn) Read(p []byte) (int, error) {
	return copy(p, c.data), nil
}

// readOne runs ReadFromAddrPort over a canned datagram.
func readOne(t *testing.T, data []byte) (int, netip.AddrPort, error) {
	t.Helper()
	pc := &PktConn{Conn: &readStubConn{data: data}}
	return pc.ReadFromAddrPort(make([]byte, 512))
}

// TestReadFromAddrPortRejectionsAreDroppable pins the datagram-dropped
// contract on the reply parser: every failure that consumed a datagram from
// the socket must carry netproxy.ErrDatagramDropped, so the consumer drops
// that one datagram instead of retiring the endpoint. (Port of
// olicesx/outbound 7f939b6.)
func TestReadFromAddrPortRejectionsAreDroppable(t *testing.T) {
	cases := map[string][]byte{
		"truncated header": {0, 0, 0, 0x01, 1, 2},                          // n < 10
		"fragment":         {0, 0, 1, 0x01, 1, 2, 3, 4, 0, 30, 9, 9},       // FRAG != 0
		"domain fast path": {0, 0, 0, 0x03, 1, 2, 3, 4, 0, 30, 9, 9},       // atyp domain
		"unknown atyp":     {0, 0, 0, 0x77, 1, 2, 3, 4, 0, 30, 9, 9},       // atyp 0x77
		"invalid tail":     {0, 0, 0, 0x04, 1, 2, 3, 4, 5, 6, 7, 8, 0, 30}, // IPv6 needs 22, n = 14
	}
	for name, data := range cases {
		_, _, err := readOne(t, data)
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		var dropped *netproxy.ErrDatagramDropped
		if !errors.As(err, &dropped) {
			t.Errorf("%s: err = %v, want the datagram-dropped contract", name, err)
		}
	}
}

// TestReadFromAddrPortCallerBufferIsNotDroppable covers the one rejection that
// is not a per-datagram event: the caller's buffer check returns before
// anything is read from the socket, so the datagram is still queued and must
// not carry the dropped contract.
func TestReadFromAddrPortCallerBufferIsNotDroppable(t *testing.T) {
	pc := &PktConn{Conn: &readStubConn{data: []byte{0, 0, 0, 0x01, 1, 2, 3, 4, 0, 30}}}
	_, _, err := pc.ReadFromAddrPort(make([]byte, 8))
	if err == nil {
		t.Fatal("expected the buffer-too-small error")
	}
	var dropped *netproxy.ErrDatagramDropped
	if errors.As(err, &dropped) {
		t.Fatalf("a pre-read precondition must not claim a datagram was dropped, got %v", err)
	}
}

// TestReadFromAddrPortHappyPath keeps the decode itself honest while the
// rejections change shape.
func TestReadFromAddrPortHappyPath(t *testing.T) {
	data := []byte{0, 0, 0, 0x01, 1, 2, 3, 4, 0, 30, 9, 9}
	n, ap, err := readOne(t, data)
	if err != nil {
		t.Fatalf("ReadFromAddrPort: %v", err)
	}
	if ap.String() != "1.2.3.4:30" {
		t.Fatalf("addr = %v, want 1.2.3.4:30", ap)
	}
	if n != 2 { // the two 0x09 payload bytes, shifted to the buffer head
		t.Fatalf("payload length = %d, want 2", n)
	}
}
