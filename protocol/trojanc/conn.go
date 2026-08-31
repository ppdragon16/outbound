package trojanc

import (
	"fmt"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

var (
	CRLF        = []byte{13, 10}
	FailAuthErr = fmt.Errorf("incorrect password")
)

const (
	CommandConnect = 0x01
	CommandUDP     = 0x03
)

type Conn struct {
	net.Conn
	addr    *socks5.AddressInfo
	command byte
	pass    [56]byte // Hex SHA224

	writeMutex sync.Mutex
	onceWrite  bool
	// writeBroken marks a connection whose framing is no longer trustworthy:
	// a short write may have left a partial frame on the wire, and the peer
	// would mis-parse anything appended after it.
	writeBroken bool
}

func ParseNetwork(n byte) string {
	switch n {
	case CommandConnect:
		return "tcp"
	case CommandUDP:
		return "udp"
	default:
		return "invalid"
	}
}

func NetworkToByte(network string) byte {
	switch network {
	case "tcp":
		return CommandConnect
	case "udp":
		return CommandUDP
	default:
		return 0
	}
}

// NewConn now accepts the pre-computed hexPass to save CPU cycles.
func NewConn(conn net.Conn, addr *socks5.AddressInfo, network string, hexPass []byte) net.Conn {
	c := &Conn{
		Conn:    conn,
		addr:    addr,
		command: NetworkToByte(network),
	}
	copy(c.pass[:], hexPass)

	if cw, ok := conn.(netproxy.CloseWriter); ok {
		return &netproxy.CloseWriteConn{Conn: c, CloseWriter: cw}
	}
	return c
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	if c.writeBroken {
		return 0, net.ErrClosed
	}

	if !c.onceWrite {
		// Calculate potential header size: Pass(56) + CRLF(2) + Cmd(1) + Addr(max 259) + CRLF(2)
		// Total max header is around 320 bytes.
		maxHeaderLen := 56 + 2 + 1 + 259 + 2
		totalLen := maxHeaderLen + len(b)

		buf := pool.GetBuffer(totalLen)
		defer pool.PutBuffer(buf)

		// 1. Write Password Hash and CRLF
		curr := copy(buf, c.pass[:])
		curr += copy(buf[curr:], CRLF)

		// 2. Write Trojan Request (Command + Address)
		buf[curr] = c.command
		curr++

		aLen, err := socks5.WriteAddrInfoInplace(c.addr, buf[curr:])
		if err != nil {
			return 0, fmt.Errorf("failed to write address: %w", err)
		}
		curr += aLen

		// 3. Write second CRLF
		curr += copy(buf[curr:], CRLF)

		// 4. Write Payload (zero-copy from 'b')
		curr += copy(buf[curr:], b)

		// Send everything in one single syscall. The password hash, command
		// and address only precede the payload in this first frame, so the
		// handshake stays uncommitted until every byte is out: a short write
		// must not let the next Write resend them.
		if _, err := iout.WriteFull(c.Conn, buf[:curr]); err != nil {
			c.writeBroken = true
			return 0, fmt.Errorf("failed to write handshake: %w", err)
		}

		c.onceWrite = true
		return len(b), nil
	}

	if _, err := iout.WriteFull(c.Conn, b); err != nil {
		c.writeBroken = true
		return 0, err
	}
	return len(b), nil
}
