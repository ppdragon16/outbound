package vless

import (
	"bytes"
	"errors"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/vmess"
)

// domainFirst4 builds the leading four bytes consumed before
// CompleteMetadataFromReader: network byte (tcp), big-endian port 80, and the
// domain address type.
func domainFirst4() []byte {
	return []byte{0x01, 0x00, 0x50, vmess.MetadataTypeToByte(protocol.MetadataTypeDomain)}
}

// TestCompleteMetadataFromReaderDomain pins the domain branch: the declared
// length is read in full and nothing beyond it, and a zero-length domain is
// rejected instead of leaving an empty hostname to route on. (Port of
// olicesx/outbound e79c02d's guard; the length fix itself is already present.)
func TestCompleteMetadataFromReaderDomain(t *testing.T) {
	domain := "example.dae"
	stream := append([]byte{byte(len(domain))}, domain...)
	// Trailing sentinel: the domain branch must consume exactly 1+len(domain)
	// bytes and leave it unread.
	stream = append(stream, 0xEE)
	r := bytes.NewReader(stream)

	var m Metadata
	if err := CompleteMetadataFromReader(&m, domainFirst4(), r); err != nil {
		t.Fatalf("CompleteMetadataFromReader: %v", err)
	}
	if m.Hostname != domain {
		t.Fatalf("hostname = %q, want %q", m.Hostname, domain)
	}
	if next, err := r.ReadByte(); err != nil || next != 0xEE {
		t.Fatalf("stream position drifted: next = %#x err = %v, want the sentinel 0xee", next, err)
	}

	// Zero-length domain: reject rather than route on an empty hostname.
	var zero Metadata
	err := CompleteMetadataFromReader(&zero, domainFirst4(), bytes.NewReader([]byte{0}))
	if err == nil {
		t.Fatal("a zero-length domain must be rejected")
	}
	if !errors.Is(err, vmess.ErrInvalidMetadata) {
		t.Fatalf("err = %v, want vmess.ErrInvalidMetadata", err)
	}
}
