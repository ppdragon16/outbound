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
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"lukechampine.com/blake3"
)

type UdpConn struct {
	net.Conn

	sessionID [8]byte
	packetID  uint64

	cipherConf         *ciphers.CipherConf2022
	blockCipherEncrypt cipher.Block
	blockCipherDecrypt cipher.Block

	pskList        [][]byte
	identityHashes [][]byte
	cipherBlocks   []cipher.Block
	uPSK           []byte
	bloom          *disk_bloom.FilterGroup

	writeCipher       cipher.AEAD
	lastReadCipher    cipher.AEAD
	lastReadSessionID [8]byte
}

func NewUdpConn(conn net.Conn, conf *ciphers.CipherConf2022, blockCipherEncrypt cipher.Block, blockCipherDecrypt cipher.Block, pskList [][]byte, uPSK []byte, bloom *disk_bloom.FilterGroup) (*UdpConn, error) {
	u := &UdpConn{
		Conn:               conn,
		cipherConf:         conf,
		blockCipherEncrypt: blockCipherEncrypt,
		blockCipherDecrypt: blockCipherDecrypt,
		pskList:            pskList,
		identityHashes:     make([][]byte, len(pskList)-1),
		cipherBlocks:       make([]cipher.Block, len(pskList)-1),
		uPSK:               uPSK,
		bloom:              bloom,
	}

	for i := 0; i < len(pskList)-1; i++ {
		// 1. 提前计算 Identity Header 需要的 Hash
		h := blake3.Sum512(pskList[i+1])
		u.identityHashes[i] = h[:16]

		// 2. 提前创建 Block Cipher
		bc, err := conf.NewBlockCipher(pskList[i])
		if err != nil {
			return nil, err
		}
		u.cipherBlocks[i] = bc
	}

	fastrand.Read(u.sessionID[:])
	wc, err := CreateCipher(u.uPSK, u.sessionID[:], u.cipherConf)
	if err != nil {
		return nil, err
	}
	u.writeCipher = wc
	return u, nil
}

func ToAddrPort(addr net.Addr) (netip.AddrPort, error) {
	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.AddrPort(), nil
	case *net.TCPAddr:
		return v.AddrPort(), nil
	default:
		return netip.ParseAddrPort(addr.String())
	}
}

func (c *UdpConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ap, err := ToAddrPort(addr)
	if err != nil {
		return 0, err
	}
	return c.WriteToAddrPort(b, ap)
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	var ap netip.AddrPort
	n, ap, err = c.ReadFromAddrPort(b)
	return n, net.UDPAddrFromAddrPort(ap), err
}

func (c *UdpConn) WriteToAddrPort(b []byte, ap netip.AddrPort) (int, error) {
	// SeparateHeader_PreEnc(16) + SeparateHeader(16) + IdentityHeaders(BlockSize * (len-1))
	//  + Header(11) + Addr(max 19) + Payload + Tag
	maxTotal := 16 + 16 + aes.BlockSize*(len(c.pskList)-1) + 11 + 19 + len(b) + c.cipherConf.TagLen
	totalBuf := pool.GetBuffer(maxTotal)
	defer pool.PutBuffer(totalBuf)

	// Separate Header (16 bytes)
	separateHeader := totalBuf[:16]
	copy(separateHeader[:8], c.sessionID[:])
	binary.BigEndian.PutUint64(separateHeader[8:16], atomic.AddUint64(&c.packetID, 1))

	buf := totalBuf[16:]
	// Encrpt Separate Header
	c.blockCipherEncrypt.Encrypt(buf[:16], separateHeader)

	// Identity Headers
	currPos := 16
	for i := 0; i < len(c.pskList)-1; i++ {
		subtle.XORBytes(buf[currPos:currPos+16], c.identityHashes[i], separateHeader)
		c.cipherBlocks[i].Encrypt(buf[currPos:currPos+16], buf[currPos:currPos+16])
		currPos += 16
	}

	// Message plaintext
	msgBuf := buf[currPos:]
	msgBuf[0] = HeaderTypeClientStream
	binary.BigEndian.PutUint64(msgBuf[1:9], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(msgBuf[9:11], 0) // No padding

	// Address info
	addr := ap.Addr()
	addrInfo := socks5.AddressInfo{IP: addr, Port: ap.Port()}
	if addr.Is4() {
		addrInfo.Type = socks5.AddressTypeIPv4
	} else {
		addrInfo.Type = socks5.AddressTypeIPv6
	}
	addrLen, err := socks5.WriteAddrInfoInplace(&addrInfo, msgBuf[11:])
	if err != nil {
		return 0, err
	}

	// Seal
	payloadOff := 11 + addrLen
	messageLen := payloadOff + copy(msgBuf[payloadOff:], b)
	c.writeCipher.Seal(msgBuf[:0], separateHeader[4:16], msgBuf[:messageLen], nil)

	if _, err = c.Conn.Write(buf[:currPos+messageLen+c.cipherConf.TagLen]); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *UdpConn) ReadFromAddrPort(b []byte) (int, netip.AddrPort, error) {
	wireBuf := pool.GetBuffer(2048)
	defer pool.PutBuffer(wireBuf)

	n, err := c.Conn.Read(wireBuf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if n < 16+c.cipherConf.TagLen {
		return 0, netip.AddrPort{}, errors.New("short packet")
	}

	// Get SessionID from Separate Header
	c.blockCipherDecrypt.Decrypt(wireBuf[:16], wireBuf[:16])
	sessionID := wireBuf[:8]
	nonce := wireBuf[4:16]

	// Payload (AEAD)
	var ciph cipher.AEAD
	if bytes.Equal(sessionID, c.lastReadSessionID[:]) && c.lastReadCipher != nil {
		ciph = c.lastReadCipher
	} else {
		ciph, err = CreateCipher(c.uPSK, sessionID, c.cipherConf)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		copy(c.lastReadSessionID[:], sessionID)
		c.lastReadCipher = ciph
	}

	// Decrypt Message in-place
	decrypted, err := ciph.Open(wireBuf[16:16], nonce, wireBuf[16:n], nil)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Message header must contain at least type(1) + time(8) + paddingLen(2)
	if len(decrypted) < 19 {
		return 0, netip.AddrPort{}, errors.New("decrypted message too short")
	}

	if decrypted[0] != HeaderTypeServerStream {
		return 0, netip.AddrPort{}, fmt.Errorf("unexpected header type: %d", decrypted[0])
	}

	// Timestamp
	ts := binary.BigEndian.Uint64(decrypted[1:9])
	if time.Unix(int64(ts), 0).Before(time.Now().Add(-ciphers.TimestampTolerance)) {
		return 0, netip.AddrPort{}, protocol.ErrReplayAttack
	}

	// Skip client session ID (8 bytes) and read padding length
	offset := 19 + int(binary.BigEndian.Uint16(decrypted[17:19]))

	// ATYP + ADDR + PORT
	if len(decrypted) < offset+1 {
		return 0, netip.AddrPort{}, errors.New("malformed address field")
	}

	atyp := socks5.AddressType(decrypted[offset])
	var ipAddr netip.Addr
	var addrFieldLen int

	switch atyp {
	case socks5.AddressTypeIPv4:
		if len(decrypted) < offset+7 {
			return 0, netip.AddrPort{}, io.ErrUnexpectedEOF
		}
		// Uses array pointer to avoid escape to heap
		ipAddr = netip.AddrFrom4(*(*[4]byte)(decrypted[offset+1 : offset+5]))
		addrFieldLen = 1 + 4 + 2
	case socks5.AddressTypeIPv6:
		if len(decrypted) < offset+19 {
			return 0, netip.AddrPort{}, io.ErrUnexpectedEOF
		}
		// Uses array pointer to avoid escape to heap
		ipAddr = netip.AddrFrom16(*(*[16]byte)(decrypted[offset+1 : offset+17]))
		addrFieldLen = 1 + 16 + 2
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("unsupported atyp: %v", atyp)
	}

	port := binary.BigEndian.Uint16(decrypted[offset+addrFieldLen-2 : offset+addrFieldLen])
	ap := netip.AddrPortFrom(ipAddr, port)

	// Payload
	dataOffset := offset + addrFieldLen
	payload := decrypted[dataOffset:]
	if len(b) < len(payload) {
		return 0, ap, io.ErrShortBuffer
	}

	return copy(b, payload), ap, nil
}
