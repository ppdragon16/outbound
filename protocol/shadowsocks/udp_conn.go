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
	return n, net.UDPAddrFromAddrPort(ap), err
}

func (c *UdpConn) WriteToAddrPort(b []byte, ap netip.AddrPort) (int, error) {
	addr := ap.Addr()
	isV4 := addr.Is4()

	// atyp(1) + ipv4/ipv6(4/16) + port(2)
	addrLen := 19
	if isV4 {
		addrLen = 7
	}

	// [Salt] [Encrypted(Address + Data + Tag)]
	totalPayloadLen := addrLen + len(b)
	totalBufLen := c.cipherConf.SaltLen + totalPayloadLen + c.cipherConf.TagLen

	buf := pool.GetBuffer(totalBufLen)
	defer pool.PutBuffer(buf)

	// Salt
	salt := c.sg.Get(buf[:c.cipherConf.SaltLen])

	plaintext := buf[c.cipherConf.SaltLen : c.cipherConf.SaltLen+totalPayloadLen]

	if isV4 {
		plaintext[0] = byte(socks5.AddressTypeIPv4)
		copy(plaintext[1:5], addr.AsSlice())
		binary.BigEndian.PutUint16(plaintext[5:7], ap.Port())
	} else {
		plaintext[0] = byte(socks5.AddressTypeIPv6)
		copy(plaintext[1:17], addr.AsSlice())
		binary.BigEndian.PutUint16(plaintext[17:19], ap.Port())
	}
	copy(plaintext[addrLen:], b)

	// Cipher
	ciph, err := CreateCipher(c.masterKey, salt, c.cipherConf)
	if err != nil {
		return 0, err
	}
	// Seal in-place
	ciph.Seal(plaintext[:0], ciphers.ZeroNonce[:c.cipherConf.NonceLen], plaintext, nil)

	_, err = c.Conn.Write(buf[:totalBufLen])
	return len(b), err
}

func (c *UdpConn) ReadFromAddrPort(b []byte) (int, netip.AddrPort, error) {
	if len(b) < c.cipherConf.SaltLen+c.cipherConf.TagLen {
		return 0, netip.AddrPort{}, fmt.Errorf("buffer too small")
	}

	n, err := c.Conn.Read(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Verify length
	if n < c.cipherConf.SaltLen+c.cipherConf.TagLen {
		return 0, netip.AddrPort{}, fmt.Errorf("packet too short")
	}

	salt := b[:c.cipherConf.SaltLen]
	if c.bloom != nil && c.bloom.ExistOrAdd(salt) {
		return 0, netip.AddrPort{}, protocol.ErrReplayAttack
	}

	ciph, err := CreateCipher(c.masterKey, salt, c.cipherConf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	decrypted, err := ciph.Open(b[c.cipherConf.SaltLen:c.cipherConf.SaltLen],
		ciphers.ZeroNonce[:c.cipherConf.NonceLen],
		b[c.cipherConf.SaltLen:n], nil)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	if len(decrypted) < 1 {
		return 0, netip.AddrPort{}, fmt.Errorf("empty decrypted payload")
	}

	atyp := socks5.AddressType(decrypted[0])
	var addr netip.Addr
	var portOffset int

	switch atyp {
	case socks5.AddressTypeIPv4:
		if len(decrypted) < 7 {
			return 0, netip.AddrPort{}, fmt.Errorf("short ipv4")
		}
		addr = netip.AddrFrom4([4]byte(decrypted[1:5]))
		portOffset = 5
	case socks5.AddressTypeIPv6:
		if len(decrypted) < 19 {
			return 0, netip.AddrPort{}, fmt.Errorf("short ipv6")
		}
		addr = netip.AddrFrom16([16]byte(decrypted[1:17]))
		portOffset = 17
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("unsupported atyp in ss: %v", atyp)
	}

	port := binary.BigEndian.Uint16(decrypted[portOffset : portOffset+2])
	ap := netip.AddrPortFrom(addr, port)

	// Payload
	dataOffset := portOffset + 2
	if len(decrypted) < dataOffset {
		return 0, ap, fmt.Errorf("no data after address")
	}

	return copy(b, decrypted[dataOffset:]), ap, nil
}
