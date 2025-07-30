package shadowsocks

import (
	"encoding/binary"
	"fmt"
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
func EncodeAddress(addr *AddressInfo) (buf []byte, n int, err error) {
	switch addr.Type {
	case AddressTypeIPv4:
		if !addr.IP.Is4() {
			return nil, 0, fmt.Errorf("invalid IPv4 address: %v", addr.Hostname)
		}
		n = 1 + 4 + 2 // type + ip + port
		buf = pool.Get(n)
		buf[0] = byte(AddressTypeIPv4)
		copy(buf[1:], addr.IP.AsSlice())
		binary.BigEndian.PutUint16(buf[5:], addr.Port)
	case AddressTypeIPv6:
		if !addr.IP.Is6() {
			return nil, 0, fmt.Errorf("invalid IPv6 address: %v", addr.Hostname)
		}
		n = 1 + 16 + 2 // type + ip + port
		buf = pool.Get(n)
		buf[0] = byte(AddressTypeIPv6)
		copy(buf[1:], addr.IP.AsSlice())
		binary.BigEndian.PutUint16(buf[17:], addr.Port)
	case AddressTypeDomain:
		lenDN := len(addr.Hostname)
		if lenDN > 255 {
			return nil, 0, fmt.Errorf("domain name too long: %d bytes", lenDN)
		}
		n = 1 + 1 + lenDN + 2 // type + len + domain + port
		buf = pool.Get(n)
		buf[0] = byte(AddressTypeDomain)
		buf[1] = uint8(lenDN)
		copy(buf[2:], addr.Hostname)
		binary.BigEndian.PutUint16(buf[2+lenDN:], addr.Port)
	default:
		return nil, 0, fmt.Errorf("unsupported address type: %v", addr.Type)
	}
	return buf, n, nil
}

// DecodeAddress decodes address from buffer
func DecodeAddress(data []byte) (info *AddressInfo, n int, err error) {
	if len(data) < 2 {
		return nil, 0, fmt.Errorf("%w: too short", ErrInvalidAddress)
	}

	info = &AddressInfo{Type: AddressType(data[0])}

	switch info.Type {
	case AddressTypeIPv4:
		if len(data) < 7 { // 1 + 4 + 2
			return nil, 0, fmt.Errorf("%w: IPv4 address too short", ErrInvalidAddress)
		}
		info.IP = netip.AddrFrom4([4]byte(data[1:5]))
		info.Port = binary.BigEndian.Uint16(data[5:7])
		n = 7
	case AddressTypeIPv6:
		if len(data) < 19 { // 1 + 16 + 2
			return nil, 0, fmt.Errorf("%w: IPv6 address too short", ErrInvalidAddress)
		}
		info.IP = netip.AddrFrom16([16]byte(data[1:17]))
		info.Port = binary.BigEndian.Uint16(data[17:19])
		n = 19
	case AddressTypeDomain:
		if len(data) < 4 { // 1 + 1 + min_domain + 2
			return nil, 0, fmt.Errorf("%w: domain address too short", ErrInvalidAddress)
		}
		domainLen := int(data[1])
		n = 1 + 1 + domainLen + 2
		if len(data) < n {
			return nil, 0, fmt.Errorf("%w: domain address too short", ErrInvalidAddress)
		}
		info.Hostname = string(data[2 : 2+domainLen])
		info.Port = binary.BigEndian.Uint16(data[2+domainLen : 4+domainLen])
	default:
		return nil, 0, fmt.Errorf("%w: invalid type: %v", ErrInvalidAddress, data[0])
	}
	return
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
