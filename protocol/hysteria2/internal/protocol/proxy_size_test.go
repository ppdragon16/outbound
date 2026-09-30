package protocol

import (
	"net/netip"
	"testing"
)

// TestUDPMessageSizeMatchesSerialize pins the accounting contract the UDP
// fragment path depends on: Size() (and HeaderSize()) must equal the number of
// bytes Serialize writes, for every address shape. The fragment writer cuts a
// message at exactly the datagram limit, so a one-byte undercount makes the
// last fragment serialize one byte over the limit and quic-go rejects it with
// "DATAGRAM frame too large".
//
// The address set covers the shapes where a canonical-text length can drift
// from netip's: a single zero group (RFC 5952 forbids compressing it - the
// shape that used to be miscounted), several zero runs of different lengths,
// an all-zero address, a scope zone, and IPv4.
func TestUDPMessageSizeMatchesSerialize(t *testing.T) {
	addrs := []string{
		"1.2.3.4:443",
		"255.255.255.255:65535",
		"0.0.0.0:0",
		"[::]:443",
		"[::1]:443",
		"[2a03:2880:f350:80:face:b00c:0:3]:443", // single zero group
		"[2001:db8:0:0:1:0:0:1]:53",             // two runs of 2: leftmost wins
		"[1:0:0:2:0:0:0:3]:1",                   // runs of 2 and 3: longest wins
		"[fe80::1%eth0]:443",                    // scope zone
		"[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
	}
	for _, raw := range addrs {
		ap := netip.MustParseAddrPort(raw)
		for _, dataLen := range []int{0, 1, 100, 1197, 1400} {
			m := UDPMessage{SessionID: 1, PacketID: 1, FragID: 0, FragCount: 1, AddrPort: ap, Data: make([]byte, dataLen)}
			buf := make([]byte, MaxUDPSize)
			n := m.Serialize(buf)
			if n != m.Size() {
				t.Errorf("%v data=%d: Serialize()=%d, Size()=%d (HeaderSize=%d)",
					ap, dataLen, n, m.Size(), m.HeaderSize())
			}
		}
	}
}
