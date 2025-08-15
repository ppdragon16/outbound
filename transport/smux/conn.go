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

func WriteStreamRequest(buf *bytes.Buffer, streamRequest *StreamRequest) error {
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
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if !c.onceWrite {
		err = WriteStreamRequest(buf, &StreamRequest{
			Destination: c.addr,
			UDP:         c.udp,
			PacketAddr:  c.packetAddr,
		})
		if err != nil {
			return
		}
		c.onceWrite = true
	}
	buf.Write(b)
	_, err = c.Conn.Write(buf.Bytes())
	return len(b), err
}
