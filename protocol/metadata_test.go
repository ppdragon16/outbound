package protocol

import (
	"net"
	"net/netip"
	"sync"
	"testing"
)

func TestParseMetadataPortBounds(t *testing.T) {
	cases := []struct {
		target  string
		wantErr bool
		want    uint16
	}{
		{"1.2.3.4:443", false, 443},
		{"[::1]:8080", false, 8080},
		{"example.com:80", false, 80},
		// Previously wrapped: Atoi + uint16 conversion mapped -1 to 65535
		// and 65536 to 0.
		{"1.2.3.4:-1", true, 0},
		{"1.2.3.4:65536", true, 0},
		{"1.2.3.4:99999", true, 0},
	}
	for _, c := range cases {
		mdata, err := ParseMetadata(c.target)
		if c.wantErr {
			if err == nil {
				t.Fatalf("ParseMetadata(%q) = %+v, want error", c.target, mdata)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseMetadata(%q): %v", c.target, err)
		}
		if mdata.Port != c.want {
			t.Fatalf("ParseMetadata(%q) port = %d, want %d", c.target, mdata.Port, c.want)
		}
	}
}

func cacheEntries(cache *sync.Map) (n int) {
	cache.Range(func(any, any) bool {
		n++
		return true
	})
	return n
}

// TestDomainIpMappingBoundsTheCache is the regression guard for the unbounded
// per-connection domain->IP cache. Its key is the hostname carried in a
// received packet's metadata, so it is chosen by the peer: measured on the
// production path, one distinct hostname per datagram retains ~165 bytes, i.e.
// ~33 MB for 200k names on a single UDP association, held until the
// association closes. The cache must stop growing at its bound without
// changing any result. (Port of koutbound d52677d.)
//
// The hostnames are IP literals, which the resolver parses without a DNS
// query, so this test needs no network.
func TestDomainIpMappingBoundsTheCache(t *testing.T) {
	var cache sync.Map
	const lookups = maxDomainIpCacheEntries * 4
	for i := 0; i < lookups; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		m := Metadata{Type: MetadataTypeDomain, Hostname: ip.String(), Port: 53}
		got, err := m.DomainIpMapping(&cache)
		if err != nil {
			t.Fatalf("lookup %d (%s): %v", i, m.Hostname, err)
		}
		// Compare against the resolver itself rather than a hand-built
		// address: the point is that the bound never changes the answer, and
		// ResolveUDPAddr's own representation (a 4-in-6 mapped address for an
		// IPv4 literal) is part of that answer.
		resolved, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), "53"))
		if err != nil {
			t.Fatalf("lookup %d: ResolveUDPAddr: %v", i, err)
		}
		if want := resolved.AddrPort(); got != want {
			t.Fatalf("lookup %d (%s): addr = %v, want %v", i, m.Hostname, got, want)
		}
	}
	if n := cacheEntries(&cache); n > maxDomainIpCacheEntries {
		t.Fatalf("cache holds %d entries after %d distinct hostnames, want <= %d",
			n, lookups, maxDomainIpCacheEntries)
	}
	if n := cacheEntries(&cache); n == 0 {
		t.Fatal("cache stored nothing; the bound must not disable caching")
	}
}

// TestDomainIpMappingCachesBelowTheBound pins the other half of the contract:
// below the bound, repeats of the same hostname stay cached.
func TestDomainIpMappingCachesBelowTheBound(t *testing.T) {
	var cache sync.Map
	mk := func(last byte) *Metadata {
		return &Metadata{Type: MetadataTypeDomain,
			Hostname: netip.AddrFrom4([4]byte{10, 0, 0, last}).String(), Port: 53}
	}
	for _, last := range []byte{1, 2, 3, 2, 1, 3} {
		if _, err := mk(last).DomainIpMapping(&cache); err != nil {
			t.Fatalf("lookup %d: %v", last, err)
		}
	}
	if n := cacheEntries(&cache); n != 3 {
		t.Fatalf("cache holds %d entries, want 3", n)
	}
}
