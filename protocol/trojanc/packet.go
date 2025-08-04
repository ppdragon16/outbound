package trojanc

import (
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

type PacketConn struct {
	*Conn
	domainIpMapping sync.Map
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	m := Metadata{}
	if _, err = m.Unpack(c.Conn); err != nil {
		return 0, nil, err
	}
	_addr, err := m.DomainIpMapping(&c.domainIpMapping)
	if err != nil {
		return 0, nil, err
	}
	addr = net.UDPAddrFromAddrPort(_addr)

	buf := pool.GetBuffer(2)
	defer pool.PutBuffer(buf)
	if _, err = io.ReadFull(c.Conn, buf[:2]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint16(buf)
	buf = pool.GetBuffer(2 + int(length))
	defer pool.PutBuffer(buf)
	if _, err = io.ReadFull(c.Conn, buf); err != nil {
		return 0, nil, err
	}
	n = copy(p, buf[2:])
	return n, addr, nil
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	_metadata, err := protocol.ParseMetadata(addr.String())
	if err != nil {
		return 0, err
	}
	metadata := Metadata{
		Metadata: _metadata,
		Network:  "udp",
	}
	buf := pool.GetBuffer(metadata.Len() + 4 + len(p))
	defer pool.PutBuffer(buf)
	SealUDP(metadata, buf, p)
	_, err = c.Conn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func SealUDP(metadata Metadata, dst []byte, data []byte) []byte {
	n := metadata.Len()
	// copy first to allow overlap
	copy(dst[n+4:], data)
	metadata.PackTo(dst)
	binary.BigEndian.PutUint16(dst[n:], uint16(len(data)))
	copy(dst[n+2:], CRLF)
	return dst[:n+4+len(data)]
}
