package smux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

type Conn struct {
	net.Conn

	addr       string
	udp        bool
	packetAddr bool

	onceRead  bool
	onceWrite bool
}

func ReadResponse(conn net.Conn) error {
	var status uint8
	err := binary.Read(conn, binary.BigEndian, &status)
	if err != nil {
		return err
	}
	if status == statusError {
		message, err := io.ReadAll(conn)
		if err != nil {
			return err
		}
		// Sanitize: remote server may include protocol-internal bytes
		// (e.g. flags, invalid UTF-8) in the error message. Strip them
		// to avoid garbled log output and downstream parsing issues.
		message = bytes.ToValidUTF8(message, nil)
		message = bytes.Map(func(r rune) rune {
			if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
				return -1
			}
			return r
		}, message)
		return errors.New("smux failed to read: " + string(message))
	}
	return nil
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if !c.onceRead {
		err = ReadResponse(c.Conn)
		if err != nil {
			return
		}
		c.onceRead = true
	}
	return c.Conn.Read(b)
}

type StreamRequest struct {
	Destination string
	UDP         bool
	PacketAddr  bool
}

func WriteStreamRequest(buf *pool.PooledBuffer, streamRequest *StreamRequest) error {
	var flags uint16
	if streamRequest.UDP {
		flags |= flagUDP
	}
	if streamRequest.PacketAddr {
		flags |= flagAddr
	}
	binary.Write(buf, binary.BigEndian, flags)
	return socks5.WriteAddr(streamRequest.Destination, buf)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if !c.onceWrite {
		buf := pool.NewPooledBuffer()
		defer buf.Reset()
		err = WriteStreamRequest(buf, &StreamRequest{
			Destination: c.addr,
			UDP:         c.udp,
			PacketAddr:  c.packetAddr,
		})
		if err != nil {
			return
		}
		c.onceWrite = true
		buf.Write(b)
		_, err = c.Conn.Write(buf.Bytes())
		return len(b), err
	}
	return c.Conn.Write(b)
}
