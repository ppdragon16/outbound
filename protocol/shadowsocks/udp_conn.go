package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
	disk_bloom "github.com/mzz2017/disk-bloom"
)

type UdpConn struct {
	net.Conn

	cipherConf *ciphers.CipherConf
	masterKey  []byte
	sg         SaltGenerator
	bloom      *disk_bloom.FilterGroup
}

func NewUdpConn(conn net.Conn, conf *ciphers.CipherConf, masterKey []byte, sg SaltGenerator, bloom *disk_bloom.FilterGroup) (*UdpConn, error) {
	return &UdpConn{
		Conn:       conn,
		cipherConf: conf,
		masterKey:  masterKey,
		sg:         sg,
		bloom:      bloom,
	}, nil
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
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(ap), nil
}

func (c *UdpConn) WriteToAddrPort(b []byte, ap netip.AddrPort) (int, error) {
	addr := ap.Addr()
	isV4 := addr.Is4()

	// 1. Calculate address field length: ATYP(1) + IP(4 or 16) + Port(2)
	addrLen := 19
	if isV4 {
		addrLen = 7
	}

	// 2. Pre-calculate total buffer size: [Salt] [Address + Data + Tag]
	totalPayloadLen := addrLen + len(b)
	totalBufLen := c.cipherConf.SaltLen + totalPayloadLen + c.cipherConf.TagLen

	buf := pool.GetBuffer(totalBufLen)
	defer pool.PutBuffer(buf)

	// 3. Handshake: Generate Salt
	salt := c.sg.Get(buf[:c.cipherConf.SaltLen])

	// 4. Construct Plaintext: [Address][Payload]
	plaintext := buf[c.cipherConf.SaltLen : c.cipherConf.SaltLen+totalPayloadLen]
	if isV4 {
		plaintext[0] = byte(socks5.AddressTypeIPv4)
		// Use fixed-size array copy to avoid slice escape
		ip4 := addr.As4()
		copy(plaintext[1:5], ip4[:])
		binary.BigEndian.PutUint16(plaintext[5:7], ap.Port())
	} else {
		plaintext[0] = byte(socks5.AddressTypeIPv6)
		ip16 := addr.As16()
		copy(plaintext[1:17], ip16[:])
		binary.BigEndian.PutUint16(plaintext[17:19], ap.Port())
	}
	copy(plaintext[addrLen:], b)

	// 5. Encrypt In-place
	ciph, err := CreateCipher(c.masterKey, salt, c.cipherConf)
	if err != nil {
		return 0, err
	}
	// Destination and Source overlap for in-place AEAD
	ciph.Seal(plaintext[:0], ciphers.ZeroNonce[:c.cipherConf.NonceLen], plaintext, nil)

	// 6. Transmit
	_, err = c.Conn.Write(buf[:totalBufLen])
	return len(b), err
}

func (c *UdpConn) ReadFromAddrPort(b []byte) (int, netip.AddrPort, error) {
	// Use pool for wire buffer to handle overhead and avoid corruption of user buffer 'b'
	wireBuf := pool.GetBuffer(2048)
	defer pool.PutBuffer(wireBuf)

	n, err := c.Conn.Read(wireBuf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Minimum length: Salt + ATYP + Port + Tag
	if n < c.cipherConf.SaltLen+c.cipherConf.TagLen+3 {
		return 0, netip.AddrPort{}, fmt.Errorf("packet too short")
	}

	// 1. Replay Protection
	salt := wireBuf[:c.cipherConf.SaltLen]
	if c.bloom != nil && c.bloom.ExistOrAdd(salt) {
		return 0, netip.AddrPort{}, protocol.ErrReplayAttack
	}

	// 2. Creates cipher
	ciph, err := CreateCipher(c.masterKey, salt, c.cipherConf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	decrypted, err := ciph.Open(wireBuf[c.cipherConf.SaltLen:c.cipherConf.SaltLen],
		ciphers.ZeroNonce[:c.cipherConf.NonceLen],
		wireBuf[c.cipherConf.SaltLen:n], nil)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	if len(decrypted) < 1 {
		return 0, netip.AddrPort{}, fmt.Errorf("empty payload")
	}

	// 3. Parse Address Header (Zero-allocation)
	atyp := socks5.AddressType(decrypted[0])
	var addr netip.Addr
	var portOffset int

	switch atyp {
	case socks5.AddressTypeIPv4:
		if len(decrypted) < 7 {
			return 0, netip.AddrPort{}, fmt.Errorf("short ipv4")
		}
		// Direct array conversion to prevent slice escape
		addr = netip.AddrFrom4(*(*[4]byte)(decrypted[1:5]))
		portOffset = 5
	case socks5.AddressTypeIPv6:
		if len(decrypted) < 19 {
			return 0, netip.AddrPort{}, fmt.Errorf("short ipv6")
		}
		addr = netip.AddrFrom16(*(*[16]byte)(decrypted[1:17]))
		portOffset = 17
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("unsupported atyp: %v", atyp)
	}

	port := binary.BigEndian.Uint16(decrypted[portOffset : portOffset+2])
	ap := netip.AddrPortFrom(addr, port)

	// 4. Deliver Data to User Buffer
	dataOffset := portOffset + 2
	payload := decrypted[dataOffset:]

	return copy(b, payload), ap, nil
}
