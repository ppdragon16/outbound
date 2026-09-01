package protocol

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/daeuniverse/outbound/common"
)

type Metadata struct {
	Type     MetadataType
	Hostname string
	Port     uint16
	// Cmd is valid only if Type is MetadataTypeMsg.
	Cmd      MetadataCmd
	Cipher   string
	IsClient bool

	// CachedAddr stores the parsed IP address for IPv4/IPv6 metadata types,
	// avoiding the string allocation and re-parse cost of net.IP.String() +
	// netip.ParseAddr(Hostname) in the hot path. Set by Unpack implementations
	// that read raw IP bytes from the wire.
	CachedAddr netip.Addr
}

func (m *Metadata) DomainIpMapping(cache *sync.Map) (addrPort netip.AddrPort, err error) {
	if m.Type == MetadataTypeDomain {
		if _addr, ok := cache.Load(m.Hostname); ok {
			addrPort = netip.AddrPortFrom(_addr.(netip.Addr), m.Port)
		} else {
			uAddr, err := common.ResolveUDPAddr(net.JoinHostPort(m.Hostname, strconv.Itoa(int(m.Port))))
			if err != nil {
				return netip.AddrPort{}, err
			}
			addrPort = uAddr.AddrPort()
			if _addr, ok = cache.LoadOrStore(m.Hostname, addrPort.Addr()); ok {
				addrPort = netip.AddrPortFrom(_addr.(netip.Addr), m.Port)
			}
		}
	} else {
		if addrPort, err = m.AddrPort(); err != nil {
			return netip.AddrPort{}, fmt.Errorf("ReadFrom AddrPort: %w", err)
		}
	}
	return addrPort, nil
}

type MetadataCmd uint8

const (
	MetadataCmdPing MetadataCmd = iota
	MetadataCmdSyncPassages
	MetadataCmdResponse
)

type MetadataType int

const (
	MetadataTypeIPv4 MetadataType = iota
	MetadataTypeIPv6
	MetadataTypeDomain
	MetadataTypeMsg
	MetadataTypeInvalid
)

func ParseMetadata(tgt string) (mdata Metadata, err error) {
	host, strPort, err := net.SplitHostPort(tgt)
	if err != nil {
		return mdata, fmt.Errorf("SplitHostPort: %w", err)
	}
	// ParseUint with an explicit 16-bit bound: Atoi followed by a uint16
	// conversion silently wrapped -1 to 65535 and 65536 to 0.
	port, err := strconv.ParseUint(strPort, 10, 16)
	if err != nil {
		return mdata, fmt.Errorf("failed to parse port: %w", err)
	}
	tgtIP, err := netip.ParseAddr(host)
	var typ MetadataType
	var cachedAddr netip.Addr
	if err != nil {
		typ = MetadataTypeDomain
	} else if tgtIP.Is4() {
		typ = MetadataTypeIPv4
		cachedAddr = tgtIP
	} else {
		typ = MetadataTypeIPv6
		cachedAddr = tgtIP
	}
	return Metadata{
		Type:       typ,
		Hostname:   host,
		Port:       uint16(port),
		CachedAddr: cachedAddr,
	}, nil
}

func (m *Metadata) AddrPort() (netip.AddrPort, error) {
	switch m.Type {
	case MetadataTypeIPv4, MetadataTypeIPv6:
		if m.CachedAddr.IsValid() {
			return netip.AddrPortFrom(m.CachedAddr, m.Port), nil
		}
		ip, err := netip.ParseAddr(m.Hostname)
		if err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPortFrom(ip, m.Port), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("bad metadata type: %v; should be ip", m.Type)
	}
}
