package shadowsocks_2022

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"github.com/samber/oops"
)

type UdpConn struct {
	net.Conn

	sessionID [8]byte
	packetID  uint64

	cipherConf  *ciphers.CipherConf2022
	blockCipher cipher.Block
	masterKey   []byte
	bloom       *disk_bloom.FilterGroup
}

func NewUdpConn(conn net.Conn, conf *ciphers.CipherConf2022, blockCipher cipher.Block, masterKey []byte, bloom *disk_bloom.FilterGroup) (*UdpConn, error) {
	u := UdpConn{
		Conn:        conn,
		cipherConf:  conf,
		blockCipher: blockCipher,
		masterKey:   masterKey,
		bloom:       bloom,
	}
	// TODO: salt generator?
	fastrand.Read(u.sessionID[:])
	return &u, nil
}

func (c *UdpConn) Close() error {
	return c.Conn.Close()
}

func (c *UdpConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// Parse target address
	targetAddr, err := shadowsocks.AddressFromString(addr.String())
	if err != nil {
		return 0, err
	}

	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)

	separateHeader := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(separateHeader)

	c.packetID++

	separateHeader.Write(c.sessionID[:])
	binary.Write(separateHeader, binary.BigEndian, c.packetID)

	separateHeaderEncrypted := pool.GetBuffer(16)
	defer pool.PutBuffer(separateHeaderEncrypted)
	c.blockCipher.Encrypt(separateHeaderEncrypted, separateHeader.Bytes())

	// TODO: DEBUG
	if len(separateHeaderEncrypted) != 16 {
		return 0, fmt.Errorf("separate header length is not 16")
	}

	buf.Write(separateHeaderEncrypted)

	message, err := EncodeMessage(HeaderTypeClientStream, uint64(time.Now().Unix()), targetAddr, b)
	defer pool.PutBytesBuffer(message)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to encode message")
	}

	// Encrypt and send
	cipher, err := CreateCipher(c.masterKey, separateHeader.Bytes()[:8], c.cipherConf)
	if err != nil {
		return 0, err
	}
	buf.Write(cipher.Seal(nil, separateHeader.Bytes()[4:16], message.Bytes(), nil))

	return c.Conn.Write(buf.Bytes())
}

func EncodeMessage(typ uint8, timestamp uint64, address *shadowsocks.AddressInfo, b []byte) (*bytes.Buffer, error) {
	addressBytes, _, err := shadowsocks.EncodeAddress(address)
	defer pool.PutBuffer(addressBytes)
	if err != nil {
		return nil, err
	}

	message := pool.GetBytesBuffer()
	// Header
	message.WriteByte(typ)
	binary.Write(message, binary.BigEndian, timestamp)
	// No padding
	binary.Write(message, binary.BigEndian, uint16(0))
	message.Write(addressBytes)
	// Payload
	message.Write(b)

	return message, nil
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	buf := pool.GetBuffer(len(b) + 16)
	defer pool.PutBuffer(buf)
	n, err = c.Conn.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	if len(buf) < 16 {
		return 0, nil, fmt.Errorf("short length to decrypt")
	}

	c.blockCipher.Decrypt(buf[:16], buf[:16])

	payload := buf[16:n]
	ciph, err := CreateCipher(c.masterKey, buf[:8], c.cipherConf)
	if err != nil {
		return 0, nil, err
	}
	payload, err = ciph.Open(payload[:0], buf[4:16], payload, nil)
	if err != nil {
		return 0, nil, err
	}

	offset := 0
	typ := uint8(payload[offset])
	offset += 1
	timestamp := time.Unix(int64(binary.BigEndian.Uint64(payload[offset:offset+8])), 0)
	offset += 8
	// clientSessionID := buf[offset : offset+8]
	offset += 8
	paddingLength := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2
	offset += int(paddingLength)

	if typ != HeaderTypeServerStream {
		return 0, nil, fmt.Errorf("received unexpected header type: %d", typ)
	}

	if timestamp.Before(time.Now().Add(-ciphers.TimestampTolerance)) {
		return 0, nil, protocol.ErrReplayAttack
	}

	// Parse address from decrypted data
	addressInfo, addressLen, err := shadowsocks.DecodeAddress(payload[offset:])
	if err != nil {
		return 0, nil, err
	}
	offset += addressLen

	// Create address object (only support IP addresses for UDP)
	switch addressInfo.Type {
	case shadowsocks.AddressTypeIPv4, shadowsocks.AddressTypeIPv6:
		addr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(addressInfo.IP, addressInfo.Port))
	default:
		return 0, nil, fmt.Errorf("unsupported address type for UDP: %v", addressInfo.Type)
	}

	// Remove address header from data
	n = copy(b, payload[offset:])
	return
}
