package common

import (
	"net"
	"testing"
)

func TestPreferredIPAddr(t *testing.T) {
	ipv4a := net.IPAddr{IP: net.ParseIP("54.179.166.68")}
	ipv4b := net.IPAddr{IP: net.ParseIP("13.212.112.87")}
	ipv6a := net.IPAddr{IP: net.ParseIP("2406:da18:d40:a100:80f1:dc88:36a6:4ecd")}
	ipv6b := net.IPAddr{IP: net.ParseIP("2406:da14:40b:ab00:5cc3:7530:b88a:3156")}

	t.Run("dual stack prefers IPv4 even when IPv6 first", func(t *testing.T) {
		got := preferredIPAddr([]net.IPAddr{ipv6a, ipv4a})
		if got == nil || got.IP.To4() == nil {
			t.Fatalf("expected IPv4, got %v", got)
		}
		if !got.IP.Equal(ipv4a.IP) {
			t.Fatalf("expected %v, got %v", ipv4a.IP, got.IP)
		}
	})

	t.Run("IPv6 only falls back to IPv6", func(t *testing.T) {
		got := preferredIPAddr([]net.IPAddr{ipv6a, ipv6b})
		if got == nil || got.IP.To4() != nil {
			t.Fatalf("expected IPv6, got %v", got)
		}
		if !got.IP.Equal(ipv6a.IP) {
			t.Fatalf("expected %v, got %v", ipv6a.IP, got.IP)
		}
	})

	t.Run("IPv4 only returns IPv4", func(t *testing.T) {
		got := preferredIPAddr([]net.IPAddr{ipv4b})
		if got == nil || got.IP.To4() == nil {
			t.Fatalf("expected IPv4, got %v", got)
		}
		if !got.IP.Equal(ipv4b.IP) {
			t.Fatalf("expected %v, got %v", ipv4b.IP, got.IP)
		}
	})

	t.Run("empty returns nil", func(t *testing.T) {
		if got := preferredIPAddr(nil); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
		if got := preferredIPAddr([]net.IPAddr{}); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})
}

func TestSortIPAddrsIPv4First(t *testing.T) {
	ipv4a := net.IPAddr{IP: net.ParseIP("54.179.166.68")}
	ipv4b := net.IPAddr{IP: net.ParseIP("13.212.112.87")}
	ipv6a := net.IPAddr{IP: net.ParseIP("2406:da18:d40:a100:80f1:dc88:36a6:4ecd")}
	ipv6b := net.IPAddr{IP: net.ParseIP("2406:da14:40b:ab00:5cc3:7530:b88a:3156")}

	got := sortIPAddrsIPv4First([]net.IPAddr{ipv6a, ipv4a, ipv6b, ipv4b})
	want := []net.IPAddr{ipv4a, ipv4b, ipv6a, ipv6b}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if !got[i].IP.Equal(want[i].IP) {
			t.Fatalf("got[%d] = %v, want %v", i, got[i].IP, want[i].IP)
		}
	}
}
