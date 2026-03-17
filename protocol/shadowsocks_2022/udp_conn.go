package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
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

	pskList      [][]byte
	cipherBlocks []cipher.Block
	uPSK         []byte
	bloom        *disk_bloom.FilterGroup

	writeCipher       cipher.AEAD
	lastReadCipher    cipher.AEAD
	lastReadSessionID [8]byte
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
	wc, err := CreateCipher(u.uPSK, u.sessionID[:], u.cipherConf)
	if err != nil {
		return nil, err
	}
	u.writeCipher = wc
	return &u, nil
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
	msgBuf := buf[currPos : currPos+messagePlainLen]

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

	// Seal in-place
	c.writeCipher.Seal(msgBuf[:0], separateHeader[4:16], msgBuf, nil)

	_, err := c.Conn.Write(buf[:totalLen])
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
	var ciph cipher.AEAD
	if bytes.Equal(sessionID, c.lastReadSessionID[:]) && c.lastReadCipher != nil {
		ciph = c.lastReadCipher
	} else {
		ciph, err = CreateCipher(c.uPSK, sessionID, c.cipherConf)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		c.lastReadSessionID = [8]byte(sessionID)
		c.lastReadCipher = ciph
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
