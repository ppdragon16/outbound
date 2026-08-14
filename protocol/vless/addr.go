package vless

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/vmess"
)

func CompleteMetadataFromReader(m *Metadata, first4 []byte, r io.Reader) (err error) {
	m.Type = vmess.ParseMetadataType(first4[3])
	switch m.Type {
	case protocol.MetadataTypeIPv4:
		buf := pool.GetBuffer(4)
		defer pool.PutBuffer(buf)
		if _, err = io.ReadFull(r, buf); err != nil {
			return err
		}
		var ip4 [4]byte
		copy(ip4[:], buf)
		m.CachedAddr = netip.AddrFrom4(ip4)
		m.Hostname = m.CachedAddr.String()
	case protocol.MetadataTypeIPv6:
		buf := pool.GetBuffer(16)
		defer pool.PutBuffer(buf)
		if _, err = io.ReadFull(r, buf); err != nil {
			return err
		}
		var ip6 [16]byte
		copy(ip6[:], buf)
		m.CachedAddr = netip.AddrFrom16(ip6)
		m.Hostname = m.CachedAddr.String()
	case protocol.MetadataTypeDomain:
		buf := pool.GetBuffer(1 + 255)
		defer pool.PutBuffer(buf)
		if _, err = io.ReadFull(r, buf[:1]); err != nil {
			return err
		}
		if _, err = io.ReadFull(r, buf[1:1+int(buf[0])]); err != nil {
			return err
		}
		m.Hostname = string(buf[1 : 1+int(buf[0])])
	case protocol.MetadataTypeMsg:
		buf := pool.GetBuffer(1)
		defer pool.PutBuffer(buf)
		if _, err = io.ReadFull(r, buf); err != nil {
			return err
		}
		m.Cmd = protocol.MetadataCmd(buf[0])
	default:
		return fmt.Errorf("CompleteMetadataFromReader: %w: invalid type: %v", vmess.ErrInvalidMetadata, first4[3])
	}
	m.Port = binary.BigEndian.Uint16(first4[1:])
	m.Network = vmess.ParseNetwork(first4[0])
	return nil
}
