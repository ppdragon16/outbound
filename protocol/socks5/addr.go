package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/outbound/pool"
)

type AddressType uint8

// Address type constants for Shadowsocks protocol
const (
	AddressTypeIPv4   AddressType = 1
	AddressTypeDomain AddressType = 3
	AddressTypeIPv6   AddressType = 4
)

var (
	ErrInvalidAddress = fmt.Errorf("invalid address")
)

// AddressInfo represents decoded address information
type AddressInfo struct {
	Type     AddressType
	Hostname string
	IP       netip.Addr
	Port     uint16
}

func WriteAddr(addr string, buf *bytes.Buffer) error {
	addressInfo, err := AddressFromString(addr)
	if err != nil {
		return err
	}
	return WriteAddrInfo(addressInfo, buf)
}

// WriteAddrInfo writes address information to buffer
func WriteAddrInfo(addr *AddressInfo, buf *bytes.Buffer) error {
	buf.WriteByte(byte(addr.Type))
	switch addr.Type {
	case AddressTypeIPv4, AddressTypeIPv6:
		buf.Write(addr.IP.AsSlice())
		binary.Write(buf, binary.BigEndian, addr.Port)
	case AddressTypeDomain:
		lenDN := len(addr.Hostname)
		if lenDN > 255 {
			return fmt.Errorf("domain name too long: %d bytes", lenDN)
		}
		buf.WriteByte(uint8(lenDN))
		buf.WriteString(addr.Hostname)
		binary.Write(buf, binary.BigEndian, addr.Port)
	default:
		return fmt.Errorf("unsupported address type: %v", addr.Type)
	}
	return nil
}

// WriteAddrInfoInplace writes address information to the given slice.
func WriteAddrInfoInplace(addr *AddressInfo, buf []byte) (int, error) {
	// 1. 手动构造 Variable Header 的地址部分
	// 布局: [Type(1)][Addr(...)][Port(2)]
	curr := 0
	if len(buf) < 1 {
		return 0, io.ErrShortBuffer
	}
	// 写入 Address Type
	buf[curr] = byte(addr.Type)
	curr += 1
	switch addr.Type {
	case AddressTypeIPv4:
		if len(buf) < curr+4+2 {
			return 0, io.ErrShortBuffer
		}
		// 注意：addr.IP.AsSlice() 可能会分配内存，直接用 addr.IP.As4()则不会
		ip4 := addr.IP.As4()
		copy(buf[curr:curr+4], ip4[:])
		curr += 4
	case AddressTypeIPv6:
		if len(buf) < curr+16+2 {
			return 0, io.ErrShortBuffer
		}
		ip16 := addr.IP.As16()
		copy(buf[curr:curr+16], ip16[:])
		curr += 16
	case AddressTypeDomain:
		lenDN := len(addr.Hostname)
		if lenDN > 255 {
			return 0, fmt.Errorf("domain name too long: %d bytes", lenDN)
		}
		if len(buf) < curr+1+lenDN+2 {
			return 0, io.ErrShortBuffer
		}
		buf[curr] = uint8(lenDN)
		copy(buf[curr+1:curr+1+lenDN], addr.Hostname)
		curr += 1 + lenDN
	default:
		return 0, fmt.Errorf("unsupported address type: %v", addr.Type)
	}
	if len(buf) < curr+2 {
		return 0, io.ErrShortBuffer
	}
	binary.BigEndian.PutUint16(buf[curr:], addr.Port)
	return curr + 2, nil
}

func ReadAddr(data io.Reader) (net.Addr, error) {
	addressInfo, err := ReadAddrInfo(data)
	if err != nil {
		return nil, err
	}

	// Create address object (only support IP addresses for UDP)
	switch addressInfo.Type {
	case AddressTypeIPv4, AddressTypeIPv6:
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(addressInfo.IP, addressInfo.Port)), nil
	default:
		return nil, fmt.Errorf("unsupported address type for UDP: %v", addressInfo.Type)
	}
}

// ReadAddr reads address from buffer
func ReadAddrInfo(data io.Reader) (*AddressInfo, error) {
	var typ uint8
	if err := binary.Read(data, binary.BigEndian, &typ); err != nil {
		return nil, fmt.Errorf("%w: too short", ErrInvalidAddress)
	}

	info := &AddressInfo{Type: AddressType(typ)}

	switch info.Type {
	case AddressTypeIPv4:
		ip := pool.GetBuffer(4)
		defer pool.PutBuffer(ip)
		if _, err := data.Read(ip); err != nil {
			return nil, fmt.Errorf("failed to read IP: %w", err)
		}
		info.IP = netip.AddrFrom4([4]byte(ip))
		if err := binary.Read(data, binary.BigEndian, &info.Port); err != nil {
			return nil, fmt.Errorf("failed to read port: %w", err)
		}
	case AddressTypeIPv6:
		ip := pool.GetBuffer(16)
		defer pool.PutBuffer(ip)
		if _, err := data.Read(ip); err != nil {
			return nil, fmt.Errorf("failed to read IP: %w", err)
		}
		info.IP = netip.AddrFrom16([16]byte(ip))
		if err := binary.Read(data, binary.BigEndian, &info.Port); err != nil {
			return nil, fmt.Errorf("failed to read port: %w", err)
		}
	case AddressTypeDomain:
		var domainLen uint8
		if err := binary.Read(data, binary.BigEndian, &domainLen); err != nil {
			return nil, fmt.Errorf("failed to read domain length: %w", err)
		}
		domain := pool.GetBuffer(int(domainLen))
		defer pool.PutBuffer(domain)
		if _, err := data.Read(domain); err != nil {
			return nil, fmt.Errorf("failed to read domain: %w", err)
		}
		info.Hostname = string(domain)
		if err := binary.Read(data, binary.BigEndian, &info.Port); err != nil {
			return nil, fmt.Errorf("failed to read port: %w", err)
		}
	default:
		return nil, fmt.Errorf("%w: invalid type: %v", ErrInvalidAddress, info.Type)
	}
	return info, nil
}

func AddressFromString(addr string) (*AddressInfo, error) {
	hostname, port_, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(port_, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", port_)
	}

	info := &AddressInfo{Port: uint16(port)}

	ip, err := netip.ParseAddr(hostname)
	if err != nil {
		info.Type = AddressTypeDomain
		info.Hostname = hostname
	} else {
		info.IP = ip
		if ip.Is4() {
			info.Type = AddressTypeIPv4
		} else {
			info.Type = AddressTypeIPv6
		}
	}
	return info, nil
}

func WriteAddrPort(ap netip.AddrPort, w io.Writer) error {
	addr := ap.Addr()
	port := ap.Port()

	if addr.Is4() {
		// ATYP(1) + IP(4) + PORT(2)
		var buf [7]byte
		buf[0] = byte(AddressTypeIPv4)
		copy(buf[1:5], addr.AsSlice())
		binary.BigEndian.PutUint16(buf[5:7], port)
		_, err := w.Write(buf[:])
		return err
	} else {
		// ATYP(1) + IP(16) + PORT(2)
		var buf [19]byte
		buf[0] = byte(AddressTypeIPv6)
		copy(buf[1:17], addr.AsSlice())
		binary.BigEndian.PutUint16(buf[17:19], port)
		_, err := w.Write(buf[:])
		return err
	}
}

func ReadAddrPort(r io.Reader) (netip.AddrPort, error) {
	var atyp [1]byte
	if _, err := r.Read(atyp[:]); err != nil {
		return netip.AddrPort{}, err
	}

	switch AddressType(atyp[0]) {
	case AddressTypeIPv4:
		var buf [6]byte // IP(4) + PORT(2)
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(buf[:4])), binary.BigEndian.Uint16(buf[4:6])), nil
	case AddressTypeIPv6:
		var buf [18]byte // IP(16) + PORT(2)
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(buf[:16])), binary.BigEndian.Uint16(buf[16:18])), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported atyp: %v", atyp[0])
	}
}
