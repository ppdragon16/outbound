// protocol spec:
// https://trojan-gfw.github.io/trojan/protocol

package trojanc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

var (
	CRLF        = []byte{13, 10}
	FailAuthErr = fmt.Errorf("incorrect password")
)

// Command constants for Trojan protocol
const (
	CommandConnect = 0x01
	CommandUDP     = 0x03
)

type Conn struct {
	net.Conn
	addr    *socks5.AddressInfo
	command byte
	pass    [56]byte

	writeMutex sync.Mutex
	onceWrite  bool
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

func NewConn(conn net.Conn, addr *socks5.AddressInfo, network string, password string) net.Conn {
	hash := sha256.New224()
	hash.Write([]byte(password))
	c := &Conn{
		Conn:    conn,
		addr:    addr,
		command: NetworkToByte(network),
		pass:    [56]byte{},
	}
	hex.Encode(c.pass[:], hash.Sum(nil))
	if _, ok := conn.(netproxy.CloseWriter); ok {
		return &netproxy.CloseWriteConn{Conn: c, CloseWriter: conn.(netproxy.CloseWriter)}
	}
	return c
}

// buildTrojanRequest builds the Trojan request according to spec:
// +-----+------+----------+----------+
// | CMD | ATYP | DST.ADDR | DST.PORT |
// +-----+------+----------+----------+
// |  1  |  1   | Variable |    2     |
// +-----+------+----------+----------+
func (c *Conn) buildTrojanRequest(buf *bytes.Buffer) error {
	// Write command
	buf.WriteByte(c.command)

	// Encode address using shadowsocks format
	err := socks5.WriteAddrInfo(c.addr, buf)
	if err != nil {
		return fmt.Errorf("failed to write address: %w", err)
	}

	return nil
}

// buildRequestHeader builds the complete Trojan request header:
// +-----------------------+---------+----------------+---------+----------+
// | hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
// +-----------------------+---------+----------------+---------+----------+
// |          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
// +-----------------------+---------+----------------+---------+----------+
func (c *Conn) buildRequestHeader(buf *bytes.Buffer, payload []byte) error {
	// Write hex(SHA224(password))
	buf.Write(c.pass[:])

	// Write CRLF
	buf.Write(CRLF)

	// Write Trojan Request
	if err := c.buildTrojanRequest(buf); err != nil {
		return err
	}

	// Write CRLF
	buf.Write(CRLF)

	// Write payload
	buf.Write(payload)

	return nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	if !c.onceWrite {
		buf := pool.GetBytesBuffer()
		defer pool.PutBytesBuffer(buf)

		if err := c.buildRequestHeader(buf, b); err != nil {
			return 0, fmt.Errorf("failed to build request header: %w", err)
		}

		if _, err := c.Conn.Write(buf.Bytes()); err != nil {
			return 0, fmt.Errorf("failed to write request header: %w", err)
		}

		c.onceWrite = true
		return len(b), nil
	}

	return c.Conn.Write(b)
}

// readReqHeader reads and validates the Trojan request header when used as server
func (c *Conn) readReqHeader() error {
	// Read password hash (56 bytes)
	passwordBuf := pool.GetBuffer(56)
	defer pool.PutBuffer(passwordBuf)

	if _, err := io.ReadFull(c.Conn, passwordBuf); err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	if !bytes.Equal(c.pass[:], passwordBuf) {
		return FailAuthErr
	}

	// Read CRLF after password
	crlfBuf := pool.GetBuffer(2)
	defer pool.PutBuffer(crlfBuf)

	if _, err := io.ReadFull(c.Conn, crlfBuf); err != nil {
		return fmt.Errorf("failed to read CRLF after password: %w", err)
	}

	if !bytes.Equal(CRLF, crlfBuf) {
		return fmt.Errorf("invalid CRLF after password")
	}

	// Read command (1 byte)
	commandBuf := pool.GetBuffer(1)
	defer pool.PutBuffer(commandBuf)

	if _, err := io.ReadFull(c.Conn, commandBuf); err != nil {
		return fmt.Errorf("failed to read command: %w", err)
	}

	c.command = commandBuf[0]

	var err error
	c.addr, err = socks5.ReadAddrInfo(c.Conn)
	if err != nil {
		return fmt.Errorf("failed to decode address: %w", err)
	}

	// Read CRLF after address
	if _, err := io.ReadFull(c.Conn, crlfBuf); err != nil {
		return fmt.Errorf("failed to read CRLF after address: %w", err)
	}

	if !bytes.Equal(CRLF, crlfBuf) {
		return fmt.Errorf("invalid CRLF after address")
	}

	return nil
}
