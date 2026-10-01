package vmess

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol"
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

// framePacketAddrDatagram builds the wire chunk for one packetaddr datagram: a
// two-byte big-endian size followed by the packet address and its payload.
func framePacketAddrDatagram(t *testing.T, addr *net.UDPAddr, payload []byte) ([]byte, netip.AddrPort) {
	t.Helper()
	addrLen := UDPAddrToPacketAddrLength(addr)
	buf := make([]byte, addrLen+len(payload))
	if err := PutPacketAddr(buf, addr); err != nil {
		t.Fatal(err)
	}
	copy(buf[addrLen:], payload)
	framed := make([]byte, 2+len(buf))
	framed[0] = byte(len(buf) >> 8)
	framed[1] = byte(len(buf))
	copy(framed[2:], buf)
	return framed, addr.AddrPort()
}

// newDirectReadPacketAddrConn wires a Conn whose next read returns framed with
// the identity cipher, so a test can drive ReadFrom without a real peer.
func newDirectReadPacketAddrConn(framed []byte) *Conn {
	c := &Conn{
		Conn: &bufferConn{Buffer: bytes.NewBuffer(framed)},
		metadata: Metadata{
			Metadata: protocol.Metadata{Type: protocol.MetadataTypeDomain, Hostname: SeqPacketMagicAddress},
			Network:  "udp",
		},
		dialTgt:         "203.0.113.10:53",
		dialTgtAddrPort: netip.MustParseAddrPort("203.0.113.10:53"),
	}
	c.initRead.Do(func() {})
	c.readChunkSizeParser = PlainChunkSizeParser{}
	c.readPaddingGenerator = PlainPaddingGenerator{}
	c.readNonceGenerator = func() []byte { return make([]byte, 12) }
	c.readBodyCipher = identityAEAD{}
	return c
}

// TestReadFromDeliversDatagramLargerThanMaxUDPSize pins the read path against
// the old MaxUDPSize (2048) staging buffer: an EDNS0-sized DNS answer over a
// VMess xudp/packetaddr node was truncated to 2048 bytes and delivered as if
// complete, regardless of the caller's buffer capacity.
func TestReadFromDeliversDatagramLargerThanMaxUDPSize(t *testing.T) {
	addr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.10:53"))
	payload := bytes.Repeat([]byte{0xC3}, 4096)
	framed, wantAddr := framePacketAddrDatagram(t, addr, payload)
	c := newDirectReadPacketAddrConn(framed)

	buf := make([]byte, 65535)
	n, gotAddr, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("n = %d, want %d: datagram was truncated to the old staging buffer", n, len(payload))
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", n, len(payload))
	}
	if gotAddr.String() != wantAddr.String() {
		t.Fatalf("addr = %v, want %v", gotAddr, wantAddr)
	}
}

// TestReadFromDropsDatagramWhenCallerBufferTooSmall pins the other half: a
// caller buffer that really cannot hold the datagram must not receive a
// truncated payload, and the drop must surface as a short buffer so a consumer
// can classify it instead of treating corruption as success.
func TestReadFromDropsDatagramWhenCallerBufferTooSmall(t *testing.T) {
	addr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.10:53"))
	payload := bytes.Repeat([]byte{0x11}, 4096)
	framed, _ := framePacketAddrDatagram(t, addr, payload)
	c := newDirectReadPacketAddrConn(framed)

	small := make([]byte, 64)
	n, _, err := c.ReadFrom(small)
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("ReadFrom err = %v, want io.ErrShortBuffer", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0: a truncated datagram must not be delivered", n)
	}
}

// identityAEAD is a no-op AEAD so a test can drive the chunk reader without
// setting up session keys.
type identityAEAD struct{}

func (identityAEAD) NonceSize() int { return 12 }
func (identityAEAD) Overhead() int  { return 0 }
func (identityAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	out := make([]byte, len(dst)+len(plaintext))
	copy(out, dst)
	copy(out[len(dst):], plaintext)
	return out
}
func (identityAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	out := make([]byte, len(dst)+len(ciphertext))
	copy(out, dst)
	copy(out[len(dst):], ciphertext)
	return out, nil
}

var _ cipher.AEAD = identityAEAD{}
