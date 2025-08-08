package shadowsocks

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
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

func (c *UdpConn) Close() error {
	return c.Conn.Close()
}

func (c *UdpConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// Parse target address
	targetAddr, err := AddressFromString(addr.String())
	if err != nil {
		return 0, err
	}

	buf := pool.GetBytesBuffer()
	payload := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	defer pool.PutBytesBuffer(payload)

	// Encode address bytes
	addressBytes, _, err := EncodeAddress(targetAddr)
	defer pool.PutBuffer(addressBytes)
	if err != nil {
		return 0, err
	}

	// Combine address and data
	payload.Write(addressBytes)
	payload.Write(b)

	// Encrypt and send
	salt := c.sg.Get()
	defer pool.PutBuffer(salt)
	buf.Write(salt)
	cipher, err := CreateCipher(c.masterKey, salt, c.cipherConf)
	if err != nil {
		return 0, err
	}
	buf.Write(cipher.Seal(nil, ciphers.ZeroNonce[:c.cipherConf.NonceLen], payload.Bytes(), nil))

	_, err = c.Conn.Write(buf.Bytes())
	return len(b), err
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	buf := pool.GetBuffer(len(b) + c.cipherConf.SaltLen + c.cipherConf.TagLen)
	defer pool.PutBuffer(buf)
	n, err = c.Conn.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	if len(buf) < c.cipherConf.SaltLen {
		return 0, nil, fmt.Errorf("short length to decrypt")
	}
	salt := buf[:c.cipherConf.SaltLen]
	if c.bloom != nil {
		if c.bloom.ExistOrAdd(salt) {
			return 0, nil, protocol.ErrReplayAttack
		}
	}
	payload := buf[c.cipherConf.SaltLen:n]
	ciph, err := CreateCipher(c.masterKey, salt, c.cipherConf)
	if err != nil {
		return 0, nil, err
	}
	payload, err = ciph.Open(payload[:0], ciphers.ZeroNonce[:c.cipherConf.NonceLen], payload, nil)
	if err != nil {
		return 0, nil, err
	}

	reader := bytes.NewReader(payload)

	// Parse address from decrypted data
	addressInfo, err := DecodeAddress(reader)
	if err != nil {
		return 0, nil, err
	}

	// Create address object (only support IP addresses for UDP)
	switch addressInfo.Type {
	case AddressTypeIPv4, AddressTypeIPv6:
		addr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(addressInfo.IP, addressInfo.Port))
	default:
		return 0, nil, fmt.Errorf("unsupported address type for UDP: %v", addressInfo.Type)
	}

	n, err = reader.Read(b)
	return
}
