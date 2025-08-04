package shadowsocks

import (
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

// EncodeAddressToPool encodes address information to buffer from pool
// The returned buffer MUST be put back to pool after use
func EncodeAddress(addr *AddressInfo) ([]byte, int, error) {
	buf := pool.GetBytesBuffer()
	buf.WriteByte(byte(addr.Type))
	switch addr.Type {
	case AddressTypeIPv4, AddressTypeIPv6:
		buf.Write(addr.IP.AsSlice())
		binary.Write(buf, binary.BigEndian, addr.Port)
	case AddressTypeDomain:
		lenDN := len(addr.Hostname)
		if lenDN > 255 {
			return nil, 0, fmt.Errorf("domain name too long: %d bytes", lenDN)
		}
		buf.WriteByte(uint8(lenDN))
		buf.WriteString(addr.Hostname)
		binary.Write(buf, binary.BigEndian, addr.Port)
	default:
		return nil, 0, fmt.Errorf("unsupported address type: %v", addr.Type)
	}
	return buf.Bytes(), buf.Len(), nil
}

// DecodeAddress decodes address from buffer
func DecodeAddress(data io.Reader) (*AddressInfo, error) {
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
