package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
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
	"lukechampine.com/blake3"
)

type UdpConn struct {
	net.Conn

	sessionID [8]byte
	packetID  uint64

	cipherConf         *ciphers.CipherConf2022
	blockCipherEncrypt cipher.Block
	blockCipherDecrypt cipher.Block

	pskList [][]byte
	uPSK    []byte
	bloom   *disk_bloom.FilterGroup
}

func NewUdpConn(conn net.Conn, conf *ciphers.CipherConf2022, blockCipherEncrypt cipher.Block, blockCipherDecrypt cipher.Block, pskList [][]byte, uPSK []byte, bloom *disk_bloom.FilterGroup) (*UdpConn, error) {
	u := UdpConn{
		Conn:               conn,
		cipherConf:         conf,
		blockCipherEncrypt: blockCipherEncrypt,
		blockCipherDecrypt: blockCipherDecrypt,
		pskList:            pskList,
		uPSK:               uPSK,
		bloom:              bloom,
	}
	// TODO: salt generator?
	fastrand.Read(u.sessionID[:])
	return &u, nil
}

func (c *UdpConn) Close() error {
	return c.Conn.Close()
}

func (c *UdpConn) writeIdentityHeader(buf *bytes.Buffer, separateHeader []byte) error {
	for i := 0; i < len(c.pskList)-1; i++ {
		identityHeader := pool.GetBuffer(aes.BlockSize)
		defer pool.PutBuffer(identityHeader)

		hash := blake3.Sum512(c.pskList[i+1])
		subtle.XORBytes(identityHeader, hash[:aes.BlockSize], separateHeader)
		b, err := c.cipherConf.NewBlockCipher(c.pskList[i])
		if err != nil {
			return err
		}
		b.Encrypt(identityHeader, identityHeader)
		buf.Write(identityHeader)
	}
	return nil
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
	c.blockCipherEncrypt.Encrypt(separateHeaderEncrypted, separateHeader.Bytes())

	// TODO: DEBUG
	if len(separateHeaderEncrypted) != 16 {
		return 0, fmt.Errorf("separate header length is not 16")
	}

	buf.Write(separateHeaderEncrypted)

	err = c.writeIdentityHeader(buf, separateHeader.Bytes())
	if err != nil {
		return 0, oops.Wrapf(err, "fail to write identity header")
	}

	message, err := EncodeMessage(HeaderTypeClientStream, uint64(time.Now().Unix()), targetAddr, b)
	defer pool.PutBytesBuffer(message)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to encode message")
	}

	// Encrypt and send
	cipher, err := CreateCipher(c.uPSK, separateHeader.Bytes()[:8], c.cipherConf)
	if err != nil {
		return 0, err
	}
	buf.Write(cipher.Seal(nil, separateHeader.Bytes()[4:16], message.Bytes(), nil))

	_, err = c.Conn.Write(buf.Bytes())
	return len(b), err
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
	// Socks Address
	message.Write(addressBytes)
	// Payload
	message.Write(b)

	return message, nil
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	buf := pool.GetBuffer(len(b) + 16 + c.cipherConf.TagLen)
	defer pool.PutBuffer(buf)
	n, err = c.Conn.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	if len(buf) < 16 {
		return 0, nil, fmt.Errorf("short length to decrypt")
	}

	c.blockCipherDecrypt.Decrypt(buf[:16], buf[:16])

	payload := buf[16:n]
	ciph, err := CreateCipher(c.uPSK, buf[:8], c.cipherConf)
	if err != nil {
		return 0, nil, err
	}
	payload, err = ciph.Open(payload[:0], buf[4:16], payload, nil)
	if err != nil {
		return 0, nil, err
	}

	// Use bytes.Reader to simplify parsing
	reader := bytes.NewReader(payload)

	// Read header type
	var typ uint8
	if err := binary.Read(reader, binary.BigEndian, &typ); err != nil {
		return 0, nil, fmt.Errorf("failed to read header type: %w", err)
	}

	// Read timestamp
	var timestampRaw uint64
	if err := binary.Read(reader, binary.BigEndian, &timestampRaw); err != nil {
		return 0, nil, fmt.Errorf("failed to read timestamp: %w", err)
	}
	timestamp := time.Unix(int64(timestampRaw), 0)

	// Skip client session ID (8 bytes)
	if _, err := reader.Seek(8, io.SeekCurrent); err != nil {
		return 0, nil, fmt.Errorf("failed to skip session ID: %w", err)
	}

	// Read padding length
	var paddingLength uint16
	if err := binary.Read(reader, binary.BigEndian, &paddingLength); err != nil {
		return 0, nil, fmt.Errorf("failed to read padding length: %w", err)
	}

	// Skip padding
	if _, err := reader.Seek(int64(paddingLength), io.SeekCurrent); err != nil {
		return 0, nil, fmt.Errorf("failed to skip padding: %w", err)
	}

	if typ != HeaderTypeServerStream {
		return 0, nil, fmt.Errorf("received unexpected header type: %d", typ)
	}

	if timestamp.Before(time.Now().Add(-ciphers.TimestampTolerance)) {
		return 0, nil, protocol.ErrReplayAttack
	}

	// Parse address from decrypted data
	addressInfo, err := shadowsocks.DecodeAddress(reader)
	if err != nil {
		return 0, nil, err
	}

	// Create address object (only support IP addresses for UDP)
	switch addressInfo.Type {
	case shadowsocks.AddressTypeIPv4, shadowsocks.AddressTypeIPv6:
		addr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(addressInfo.IP, addressInfo.Port))
	default:
		return 0, nil, fmt.Errorf("unsupported address type for UDP: %v", addressInfo.Type)
	}

	// Copy remaining data to output buffer
	n, err = reader.Read(b)
	return
}
