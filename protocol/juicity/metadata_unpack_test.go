package juicity

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
)

// TestMetadataUnpackFullLengthDomain pins the header-size fix: a legal
// 253..255 byte hostname previously sliced a 256-byte buffer out of bounds
// (4+255 > 256) and the byte-width length arithmetic wrapped mod 256.
func TestMetadataUnpackFullLengthDomain(t *testing.T) {
	for _, domainLen := range []int{252, 253, 254, 255} {
		hostname := bytes.Repeat([]byte("a"), domainLen)
		wire := append([]byte{3 /* MetadataTypeDomain */, byte(domainLen)}, hostname...)
		wire = binary.BigEndian.AppendUint16(wire, 443)

		m := &Metadata{}
		n, err := m.Unpack(bytes.NewReader(wire))
		if err != nil {
			t.Fatalf("domainLen %d: Unpack: %v", domainLen, err)
		}
		if n != 4+domainLen {
			t.Fatalf("domainLen %d: Unpack returned %d, want %d", domainLen, n, 4+domainLen)
		}
		if m.Hostname != string(hostname) {
			t.Fatalf("domainLen %d: hostname truncated/corrupted: %d bytes", domainLen, len(m.Hostname))
		}
		if m.Port != 443 {
			t.Fatalf("domainLen %d: port = %d, want 443", domainLen, m.Port)
		}
		if m.Type != protocol.MetadataTypeDomain {
			t.Fatalf("domainLen %d: type = %v, want domain", domainLen, m.Type)
		}
	}
}
