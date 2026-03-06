package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
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

	pskList      [][]byte
	cipherBlocks []cipher.Block
	uPSK         []byte
	bloom        *disk_bloom.FilterGroup
}

func NewUdpConn(conn net.Conn, conf *ciphers.CipherConf2022, blockCipherEncrypt cipher.Block, blockCipherDecrypt cipher.Block, pskList [][]byte, uPSK []byte, bloom *disk_bloom.FilterGroup) (*UdpConn, error) {
	u := UdpConn{
		Conn:               conn,
		cipherConf:         conf,
		blockCipherEncrypt: blockCipherEncrypt,
		blockCipherDecrypt: blockCipherDecrypt,
		pskList:            pskList,
		cipherBlocks:       make([]cipher.Block, len(pskList)-1),
		uPSK:               uPSK,
		bloom:              bloom,
	}
	for i := 0; i < len(pskList)-1; i++ {
		bc, err := conf.NewBlockCipher(pskList[i])
		if err != nil {
			return nil, err
		}
		u.cipherBlocks[i] = bc
	}
	// TODO: salt generator?
	fastrand.Read(u.sessionID[:])
	return &u, nil
}

func (c *UdpConn) writeIdentityHeader(buf *bytes.Buffer, separateHeader []byte) error {
	for i := 0; i < len(c.pskList)-1; i++ {
		identityHeader := pool.GetBuffer(aes.BlockSize)
		defer pool.PutBuffer(identityHeader)

		hash := blake3.Sum512(c.pskList[i+1])
		subtle.XORBytes(identityHeader, hash[:aes.BlockSize], separateHeader)
		c.cipherBlocks[i].Encrypt(identityHeader, identityHeader)
		buf.Write(identityHeader)
	}
	return nil
}

func (c *UdpConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)

	c.packetID++

	var separateHeader [16]byte
	copy(separateHeader[:8], c.sessionID[:])
	binary.BigEndian.PutUint64(separateHeader[8:16], c.packetID)

	separateHeaderEncrypted := pool.GetBuffer(16)
	defer pool.PutBuffer(separateHeaderEncrypted)
	c.blockCipherEncrypt.Encrypt(separateHeaderEncrypted, separateHeader[:])
	// TODO: DEBUG
	if len(separateHeaderEncrypted) != 16 {
		return 0, fmt.Errorf("separate header length is not 16")
	}

	buf.Write(separateHeaderEncrypted)

	err := c.writeIdentityHeader(buf, separateHeader[:])
	if err != nil {
		return 0, oops.Wrapf(err, "fail to write identity header")
	}

	message, err := EncodeMessage(HeaderTypeClientStream, uint64(time.Now().Unix()), addr.String(), b)
	defer pool.PutBytesBuffer(message)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to encode message")
	}

	// Encrypt and send
	cipher, err := CreateCipher(c.uPSK, separateHeader[:8], c.cipherConf)
	if err != nil {
		return 0, err
	}
	buf.Write(cipher.Seal(nil, separateHeader[4:16], message.Bytes(), nil))

	_, err = c.Conn.Write(buf.Bytes())
	return len(b), err
}

func EncodeMessage(typ uint8, timestamp uint64, address string, b []byte) (*bytes.Buffer, error) {
	message := pool.GetBytesBuffer()
	// Header
	message.WriteByte(typ)
	binary.Write(message, binary.BigEndian, timestamp)
	// No padding
	binary.Write(message, binary.BigEndian, uint16(0))
	// Socks Address
	if err := socks5.WriteAddr(address, message); err != nil {
		pool.PutBytesBuffer(message)
		return nil, err
	}
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
	if n < 16 {
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
	if timestamp.Before(time.Now().Add(-ciphers.TimestampTolerance)) {
		return 0, nil, protocol.ErrReplayAttack
	}

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
	if paddingLength > 0 {
		if _, err := reader.Seek(int64(paddingLength), io.SeekCurrent); err != nil {
			return 0, nil, fmt.Errorf("failed to skip padding: %w", err)
		}
	}

	if typ != HeaderTypeServerStream {
		return 0, nil, fmt.Errorf("received unexpected header type: %d", typ)
	}

	// Parse address from decrypted data
	addr, err = socks5.ReadAddr(reader)
	if err != nil {
		return 0, nil, err
	}

	// Copy remaining data to output buffer
	n, err = reader.Read(b)
	return
}

func (c *UdpConn) WriteToAddrPort(b []byte, ap netip.AddrPort) (int, error) {
	c.packetID++

	// Separate Header (16 bytes)
	var separateHeader [16]byte
	copy(separateHeader[:8], c.sessionID[:])
	binary.BigEndian.PutUint64(separateHeader[8:16], c.packetID)

	// Addr length
	addr := ap.Addr()
	addrLen := 7 // atyp(1) + ipv4(4) + port(2)
	if addr.Is6() {
		addrLen = 19
	}

	// SeparateHeader(16) + IdentityHeaders(BlockSize * (len-1)) + Message(1 + 8 + 2 + addrLen + payload) + Tag
	identityHeadersLen := aes.BlockSize * (len(c.pskList) - 1)
	messagePlainLen := 1 + 8 + 2 + addrLen + len(b)
	totalLen := 16 + identityHeadersLen + messagePlainLen + c.cipherConf.TagLen

	buf := pool.GetBuffer(totalLen)
	defer pool.PutBuffer(buf)

	// Encrpt Separate Header
	c.blockCipherEncrypt.Encrypt(buf[:16], separateHeader[:])

	// Identity Headers
	currPos := 16
	for i := 0; i < len(c.pskList)-1; i++ {
		hash := blake3.Sum512(c.pskList[i+1])
		subtle.XORBytes(buf[currPos:currPos+16], hash[:16], separateHeader[:])
		c.cipherBlocks[i].Encrypt(buf[currPos:currPos+16], buf[currPos:currPos+16])
		currPos += 16
	}

	// Message plaintext
	msgBuf := pool.GetBuffer(messagePlainLen)
	defer pool.PutBuffer(msgBuf)

	msgBuf[0] = HeaderTypeClientStream
	binary.BigEndian.PutUint64(msgBuf[1:9], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(msgBuf[9:11], 0) // No padding

	if addr.Is4() {
		msgBuf[11] = byte(socks5.AddressTypeIPv4)
		copy(msgBuf[12:16], addr.AsSlice())
		binary.BigEndian.PutUint16(msgBuf[16:18], ap.Port())
	} else {
		msgBuf[11] = byte(socks5.AddressTypeIPv6)
		copy(msgBuf[12:28], addr.AsSlice())
		binary.BigEndian.PutUint16(msgBuf[28:30], ap.Port())
	}
	copy(msgBuf[11+addrLen:], b)

	cipher, err := CreateCipher(c.uPSK, separateHeader[:8], c.cipherConf)
	if err != nil {
		return 0, err
	}
	// encrypt message and append ciphertext to buffer
	ciphertext := cipher.Seal(nil, separateHeader[4:16], msgBuf, nil)
	buf = append(buf[:currPos], ciphertext...)

	_, err = c.Conn.Write(buf)
	return len(b), err
}

func (c *UdpConn) ReadFromAddrPort(b []byte) (int, netip.AddrPort, error) {
	if len(b) < 16+c.cipherConf.TagLen {
		return 0, netip.AddrPort{}, errors.New("buffer too small")
	}

	n, err := c.Conn.Read(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if n < 16+c.cipherConf.TagLen {
		return 0, netip.AddrPort{}, errors.New("short packet")
	}

	// Get SessionID from Separate Header
	c.blockCipherDecrypt.Decrypt(b[:16], b[:16])
	sessionID := b[:8]
	nonce := b[4:16]

	// Payload (AEAD)
	ciph, err := CreateCipher(c.uPSK, sessionID, c.cipherConf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	decrypted, err := ciph.Open(b[16:16], nonce, b[16:n], nil)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Message header must contain at least type(1) + time(8) + paddingLen(2)
	if len(decrypted) < 11 {
		return 0, netip.AddrPort{}, errors.New("decrypted too short")
	}

	typ := decrypted[0]
	if typ != HeaderTypeServerStream {
		return 0, netip.AddrPort{}, fmt.Errorf("unexpected header type: %d", typ)
	}

	timestampRaw := binary.BigEndian.Uint64(decrypted[1:9])
	if time.Unix(int64(timestampRaw), 0).Before(time.Now().Add(-ciphers.TimestampTolerance)) {
		return 0, netip.AddrPort{}, protocol.ErrReplayAttack
	}

	// Skip client session ID (8 bytes) and read padding length
	paddingLen := binary.BigEndian.Uint16(decrypted[17:19])
	offset := 19 + int(paddingLen)

	// ATYP + ADDR + PORT
	if len(decrypted) < offset+1 {
		return 0, netip.AddrPort{}, errors.New("no address field")
	}

	atyp := socks5.AddressType(decrypted[offset])
	var ipAddr netip.Addr
	var addrFieldLen int

	switch atyp {
	case socks5.AddressTypeIPv4:
		ipAddr = netip.AddrFrom4([4]byte(decrypted[offset+1 : offset+5]))
		addrFieldLen = 1 + 4 + 2
	case socks5.AddressTypeIPv6:
		ipAddr = netip.AddrFrom16([16]byte(decrypted[offset+1 : offset+17]))
		addrFieldLen = 1 + 16 + 2
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("unsupported atyp: %v", atyp)
	}

	port := binary.BigEndian.Uint16(decrypted[offset+addrFieldLen-2 : offset+addrFieldLen])
	ap := netip.AddrPortFrom(ipAddr, port)

	// Payload
	dataOffset := offset + addrFieldLen
	return copy(b, decrypted[dataOffset:]), ap, nil
}
