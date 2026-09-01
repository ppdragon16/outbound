package shadowsocks_stream

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
)

type readOnlyConn struct {
	*bytes.Reader
	reads   int
	maxRead int
}

func (c *readOnlyConn) Read(p []byte) (int, error) {
	c.reads++
	if c.maxRead > 0 && len(p) > c.maxRead {
		p = p[:c.maxRead]
	}
	return c.Reader.Read(p)
}

func (c *readOnlyConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (c *readOnlyConn) Close() error                     { return nil }
func (c *readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (c *readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *readOnlyConn) SetWriteDeadline(time.Time) error { return nil }
func (c *readOnlyConn) LocalAddr() net.Addr              { return nil }
func (c *readOnlyConn) RemoteAddr() net.Addr             { return nil }

func encryptedStream(t *testing.T, method string, plaintext []byte) ([]byte, *ciphers.StreamCipher) {
	t.Helper()

	encryptor, err := ciphers.NewStreamCipher(method, "test-password")
	if err != nil {
		t.Fatal(err)
	}
	iv, err := encryptor.InitEncrypt()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(plaintext))
	encryptor.Encrypt(ciphertext, plaintext)
	wire := append(append([]byte(nil), iv...), ciphertext...)

	decryptor, err := ciphers.NewStreamCipher(method, "test-password")
	if err != nil {
		t.Fatal(err)
	}
	return wire, decryptor
}

func TestTcpConnFirstReadWithExactIVSizedBuffer(t *testing.T) {
	wire, decryptor := encryptedStream(t, "aes-256-cfb", []byte("hello"))
	underlay := &readOnlyConn{
		Reader:  bytes.NewReader(wire),
		maxRead: decryptor.InfoIVLen(),
	}
	conn := NewTcpConn(underlay, decryptor)
	buf := make([]byte, decryptor.InfoIVLen())

	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got, want := string(buf[:n]), "hello"; got != want {
		t.Fatalf("Read() = %q, want %q", got, want)
	}
	if underlay.reads != 2 {
		t.Fatalf("underlay reads = %d, want 2", underlay.reads)
	}
}

func TestTcpConnFirstReadRetainsIV(t *testing.T) {
	wire, decryptor := encryptedStream(t, "aes-256-cfb", []byte("x"))
	ivLen := decryptor.InfoIVLen()
	wantIV := bytes.Clone(wire[:ivLen])
	conn := NewTcpConn(&readOnlyConn{Reader: bytes.NewReader(wire)}, decryptor)
	buf := make([]byte, ivLen+1)

	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got := decryptor.IV(); !bytes.Equal(got, wantIV) {
		t.Fatalf("retained IV = %x, want %x", got, wantIV)
	}
}

func TestTcpConnZeroLengthReadDoesNotConsumeIV(t *testing.T) {
	wire, decryptor := encryptedStream(t, "aes-256-cfb", []byte("hello"))
	underlay := &readOnlyConn{Reader: bytes.NewReader(wire)}
	conn := NewTcpConn(underlay, decryptor)

	n, err := conn.Read(make([]byte, 0))
	if err != nil || n != 0 {
		t.Fatalf("Read(empty) = (%d, %v), want (0, nil)", n, err)
	}
	if underlay.reads != 0 {
		t.Fatalf("Read(empty) consumed the underlay: reads = %d", underlay.reads)
	}
	if decryptor.DecryptInited() {
		t.Fatal("Read(empty) initialized the decryptor")
	}
}
