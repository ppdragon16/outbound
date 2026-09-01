package proto

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type oneByteReadConn struct {
	data  []byte
	reads int
}

func (c *oneByteReadConn) Read(p []byte) (int, error) {
	c.reads++
	if len(c.data) == 0 {
		return 0, net.ErrClosed
	}
	p[0] = c.data[0]
	c.data = c.data[1:]
	return 1, nil
}

func (c *oneByteReadConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (c *oneByteReadConn) Close() error                     { return nil }
func (c *oneByteReadConn) SetDeadline(time.Time) error      { return nil }
func (c *oneByteReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *oneByteReadConn) SetWriteDeadline(time.Time) error { return nil }
func (c *oneByteReadConn) LocalAddr() net.Addr              { return nil }
func (c *oneByteReadConn) RemoteAddr() net.Addr             { return nil }

type fixedFrameProtocol struct {
	frameLen  int
	skipFrame byte
}

func (*fixedFrameProtocol) InitWithServerInfo(*ServerInfo) {}
func (*fixedFrameProtocol) Encode(data []byte) ([]byte, error) {
	return data, nil
}
func (p *fixedFrameProtocol) Decode(data []byte) ([]byte, int, error) {
	if p.skipFrame != 0 && len(data) > 0 && data[0] == p.skipFrame {
		return nil, 1, nil
	}
	if len(data) < p.frameLen {
		return nil, 0, nil
	}
	return data[:p.frameLen], p.frameLen, nil
}
func (*fixedFrameProtocol) EncodePkt(buf *bytes.Buffer) error { return nil }
func (*fixedFrameProtocol) DecodePkt(data []byte) ([]byte, error) {
	return append([]byte(nil), data...), nil
}
func (*fixedFrameProtocol) SetData(interface{})  {}
func (*fixedFrameProtocol) GetData() interface{} { return nil }
func (*fixedFrameProtocol) GetOverhead() int     { return 0 }

func TestConnZeroLengthReadPreservesBufferedData(t *testing.T) {
	conn := &Conn{readLater: bytes.NewReader([]byte("payload"))}

	n, err := conn.Read(nil)
	if err != nil || n != 0 {
		t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	buf := make([]byte, len("payload"))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got, want := string(buf[:n]), "payload"; got != want {
		t.Fatalf("Read() = %q, want %q", got, want)
	}
}

func TestConnReadSkipsEmptyDecodedFrame(t *testing.T) {
	underlay := &oneByteReadConn{data: []byte("!payload")}
	conn := &Conn{
		Conn: underlay,
		Protocol: &fixedFrameProtocol{
			frameLen:  len("payload"),
			skipFrame: '!',
		},
		underPostdecryptBuf: new(bytes.Buffer),
	}
	buf := make([]byte, len("payload"))

	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got, want := string(buf[:n]), "payload"; got != want {
		t.Fatalf("Read() = %q, want %q", got, want)
	}
	if underlay.reads != len("!payload") {
		t.Fatalf("underlay reads = %d, want %d", underlay.reads, len("!payload"))
	}
}

func TestConnReadPreservesDecodedRemainder(t *testing.T) {
	underlay := &oneByteReadConn{data: []byte("payloadanother")}
	conn := &Conn{
		Conn:                underlay,
		Protocol:            &fixedFrameProtocol{frameLen: len("payload")},
		underPostdecryptBuf: new(bytes.Buffer),
	}
	buf := make([]byte, 3)
	var got []byte
	for len(got) < len("payloadanother") {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if want := "payloadanother"; string(got) != want {
		t.Fatalf("Read() stream = %q, want %q", got, want)
	}
}

func TestConnReadCollectsFragmentedFrame(t *testing.T) {
	underlay := &oneByteReadConn{data: []byte("payload")}
	conn := &Conn{
		Conn:                underlay,
		Protocol:            &fixedFrameProtocol{frameLen: len("payload")},
		underPostdecryptBuf: new(bytes.Buffer),
	}
	buf := make([]byte, len("payload"))

	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got, want := string(buf[:n]), "payload"; got != want {
		t.Fatalf("Read() = %q, want %q", got, want)
	}
	if underlay.reads != len("payload") {
		t.Fatalf("underlay reads = %d, want %d", underlay.reads, len("payload"))
	}
}
