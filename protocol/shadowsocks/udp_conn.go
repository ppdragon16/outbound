package shadowsocks

import (
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

	// Encode address bytes
	addressBytes, addressLen, err := EncodeAddress(targetAddr)
	if err != nil {
		return 0, err
	}
	defer pool.Put(addressBytes)

	// Combine address and data
	chunk := pool.Get(addressLen + len(b))
	defer pool.Put(chunk)
	copy(chunk, addressBytes)
	copy(chunk[len(addressBytes):], b)

	// Encrypt and send
	salt := c.sg.Get()
	toWrite, err := EncryptUDPFromPool(&Key{
		CipherConf: c.cipherConf,
		MasterKey:  c.masterKey,
	}, chunk, salt, ciphers.ShadowsocksReusedInfo)
	pool.Put(salt)
	if err != nil {
		return 0, err
	}
	defer pool.Put(toWrite)
	if c.bloom != nil {
		c.bloom.ExistOrAdd(toWrite[:c.cipherConf.SaltLen])
	}
	return c.Conn.Write(toWrite)
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	enc := pool.Get(len(b) + c.cipherConf.SaltLen)
	defer pool.Put(enc)
	n, err = c.Conn.Read(enc)
	if err != nil {
		return 0, nil, err
	}

	n, err = DecryptUDP(b, &Key{
		CipherConf: c.cipherConf,
		MasterKey:  c.masterKey,
	}, enc[:n], ciphers.ShadowsocksReusedInfo)
	if err != nil {
		return 0, nil, err
	}

	if c.bloom != nil {
		if exist := c.bloom.ExistOrAdd(enc[:c.cipherConf.SaltLen]); exist {
			err = protocol.ErrReplayAttack
			return
		}
	}

	// Parse address from decrypted data
	addressInfo, addressLen, err := DecodeAddress(b)
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

	// Remove address header from data
	copy(b, b[addressLen:])
	n -= addressLen
	return n, addr, nil
}
