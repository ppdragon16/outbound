package simpleobfs

import (
	"bytes"
	"io"
	"net"
	"testing"
)

// fragmentedConn serves the writes it received as reads, splitting the first
// response into arbitrarily fragmented chunks, as TCP segments do in practice.
type fragmentedConn struct {
	net.Conn
	chunks []chunk
	i      int
}

type chunk struct {
	b   []byte
	sep bool // insert an EOF error after this chunk
}

func (c *fragmentedConn) Read(p []byte) (int, error) {
	if c.i >= len(c.chunks) {
		return 0, io.EOF
	}
	ch := c.chunks[c.i]
	c.i++
	n := copy(p, ch.b)
	return n, nil
}

func (c *fragmentedConn) Write(p []byte) (int, error) { return len(p), nil }

// TestReadFirstResponseStraddlesSegments verifies a "\r\n\r\n"-terminated
// header split across multiple reads is accumulated instead of aborting the
// stream, and that body bytes riding behind the terminator in the same read
// are delivered (the fast-relay case that once tripped the size bound).
func TestReadFirstResponseStraddlesSegments(t *testing.T) {
	header1 := "HTTP/1.1 200 OK\r\nContent-"
	header2 := "Length: 0\r\n\r\n"
	body := bytes.Repeat([]byte("x"), 4096) // full header + body in one read

	c := &fragmentedConn{chunks: []chunk{
		{b: []byte(header1)},
		{b: append([]byte(header2), body...)},
	}}
	ho := NewHTTPObfs(c, "h", "80", "/").(*HTTPObfs)

	out := make([]byte, len(body))
	total := 0
	for total < len(out) {
		n, err := ho.Read(out[total:])
		if err != nil {
			t.Fatalf("Read at %d: %v", total, err)
		}
		total += n
	}
	if !bytes.Equal(out, body) {
		t.Fatalf("body mismatch: got %d bytes, prefix %q", total, out[:32])
	}
}

// TestReadFirstResponseRejectsOversizedHeader verifies the accumulation is
// still bounded once no terminator shows up.
func TestReadFirstResponseRejectsOversizedHeader(t *testing.T) {
	oversized := bytes.Repeat([]byte("a"), maxResponseHeaderSize+1)
	c := &fragmentedConn{chunks: []chunk{
		{b: oversized[:maxResponseHeaderSize]},
		{b: oversized[maxResponseHeaderSize:]},
	}}
	ho := NewHTTPObfs(c, "h", "80", "/").(*HTTPObfs)
	buf := make([]byte, 1<<15)
	if _, err := ho.Read(buf); err == nil {
		t.Fatal("expected oversized-header error")
	}
}
