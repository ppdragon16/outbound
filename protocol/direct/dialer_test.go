package direct

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDialContext_IPDirect(t *testing.T) {
	d := &directDialer{
		dialer:   &net.Dialer{Timeout: 50 * time.Millisecond},
		option:   Option{CacheTTL: 30 * time.Minute},
		dnsCache: make(map[string]*dnsCacheEntry),
	}

	ctx := context.Background()
	conn, err := d.DialContext(ctx, "tcp", "1.2.3.4:443")
	if conn != nil {
		conn.Close()
	}
	t.Logf("DialContext with IP: err=%v", err)
}

func TestDialContext_MalformedAddr(t *testing.T) {
	d := &directDialer{
		dialer:   &net.Dialer{Timeout: 50 * time.Millisecond},
		option:   Option{CacheTTL: 30 * time.Minute},
		dnsCache: make(map[string]*dnsCacheEntry),
	}

	ctx := context.Background()
	_, err := d.DialContext(ctx, "tcp", "not-an-address")
	if err == nil {
		t.Error("expected error for malformed address")
	}
}

func TestCacheHit_Ips0IsNextAddr(t *testing.T) {
	d := &directDialer{
		dnsCache: map[string]*dnsCacheEntry{
			"example.com:443": {
				ips:      []string{"10.0.0.2:443", "10.0.0.1:443"},
				expireAt: time.Now().Add(1 * time.Hour),
			},
		},
		dnsCacheMu: sync.RWMutex{},
	}

	entry, ok := d.dnsCache["example.com:443"]
	if !ok {
		t.Fatal("cache entry missing")
	}
	if entry.ips[0] != "10.0.0.2:443" {
		t.Errorf("expected ips[0]=10.0.0.2:443, got %s", entry.ips[0])
	}
}

func TestInvalidateCache(t *testing.T) {
	d := &directDialer{
		dnsCache: map[string]*dnsCacheEntry{
			"example.com:443": {
				ips:      []string{"10.0.0.1:443", "10.0.0.2:443"},
				expireAt: time.Now().Add(1 * time.Hour),
			},
		},
		dnsCacheMu: sync.RWMutex{},
	}

	d.invalidateCache("example.com:443")
	_, ok := d.dnsCache["example.com:443"]
	if ok {
		t.Error("cache entry should have been removed")
	}
}

func TestTryCachedIPs_FallbackToNextIP(t *testing.T) {
	// Start a real TCP listener on 127.0.0.1.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	goodPort := listener.Addr().(*net.TCPAddr).Port

	badAddr := "192.0.2.1:" + fmt.Sprint(goodPort)
	goodAddr := fmt.Sprintf("127.0.0.1:%d", goodPort)

	d := &directDialer{
		dialer:   &net.Dialer{Timeout: 200 * time.Millisecond},
		option:   Option{CacheTTL: 30 * time.Minute},
		dnsCache: make(map[string]*dnsCacheEntry),
	}

	// Pre-populate cache with ip:port entries.
	entry := &dnsCacheEntry{
		ips:      []string{badAddr, goodAddr},
		expireAt: time.Now().Add(1 * time.Hour),
	}
	cacheKey := "test.example.com:" + fmt.Sprint(goodPort)
	d.dnsCache[cacheKey] = entry

	// tryCachedIPs should fail on ips[0], fall back to ips[1], succeed.
	ctx := context.Background()
	conn, err := d.tryCachedIPs(ctx, "tcp", entry)
	if err != nil {
		t.Fatalf("tryCachedIPs should have succeeded via fallback addr: %v", err)
	}
	conn.Close()

	// Failed addr trimmed; ips[0] is now the working addr.
	if entry.ips[0] != goodAddr {
		t.Errorf("expected ips[0]=%s, got %s", goodAddr, entry.ips[0])
	}
	if len(entry.ips) != 1 {
		t.Errorf("expected 1 remaining addr after trim, got %d: %v", len(entry.ips), entry.ips)
	}
}

func TestTryCachedIPs_AllFailInvalidates(t *testing.T) {
	d := &directDialer{
		dialer: &net.Dialer{Timeout: 50 * time.Millisecond},
		option: Option{CacheTTL: 30 * time.Minute},
		dnsCache: map[string]*dnsCacheEntry{
			"bad.example.com:443": {
				ips:      []string{"192.0.2.1:443", "192.0.2.2:443"},
				expireAt: time.Now().Add(1 * time.Hour),
			},
		},
		dnsCacheMu: sync.RWMutex{},
	}

	entry := d.dnsCache["bad.example.com:443"]
	ctx := context.Background()
	_, err := d.tryCachedIPs(ctx, "tcp", entry)
	if err == nil {
		t.Fatal("expected all cached addrs to fail")
	}

	// Simulate what dialDomain does: Phase 1 fails → invalidate cache.
	d.invalidateCache("bad.example.com:443")

	_, ok := d.dnsCache["bad.example.com:443"]
	if ok {
		t.Error("cache should be invalidated after all IPs fail")
	}
}

func TestResolveAllIPs_Sorting(t *testing.T) {
	ips, err := sortIPsForTest([]net.IP{
		net.ParseIP("::1"),
		net.ParseIP("10.0.0.1"),
		net.ParseIP("::2"),
		net.ParseIP("10.0.0.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 4 {
		t.Fatalf("expected 4 IPs, got %d", len(ips))
	}
	if ips[0] != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1 first, got %s", ips[0])
	}
	if ips[1] != "10.0.0.2" {
		t.Errorf("expected 10.0.0.2 second, got %s", ips[1])
	}
	if ips[2] != "::1" {
		t.Errorf("expected ::1 third, got %s", ips[2])
	}
	if ips[3] != "::2" {
		t.Errorf("expected ::2 fourth, got %s", ips[3])
	}
}

func TestResolveAllIPs_OnlyIPv4(t *testing.T) {
	ips, err := sortIPsForTest([]net.IP{
		net.ParseIP("10.0.0.2"),
		net.ParseIP("10.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d", len(ips))
	}
	if ips[0] != "10.0.0.2" || ips[1] != "10.0.0.1" {
		t.Errorf("expected original order preserved: [10.0.0.2, 10.0.0.1], got %v", ips)
	}
}

func TestResolveAllIPs_OnlyIPv6(t *testing.T) {
	ips, err := sortIPsForTest([]net.IP{
		net.ParseIP("::2"),
		net.ParseIP("::1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d", len(ips))
	}
	if ips[0] != "::2" || ips[1] != "::1" {
		t.Errorf("expected original order preserved: [::2, ::1], got %v", ips)
	}
}

// sortIPsForTest replicates the sorting logic in resolveAllIPs.
func sortIPsForTest(addrs []net.IP) ([]string, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no IPs")
	}
	var ips []string
	for _, ip := range addrs {
		if ip.To4() != nil {
			ips = append(ips, ip.String())
		}
	}
	for _, ip := range addrs {
		if ip.To4() == nil {
			ips = append(ips, ip.String())
		}
	}
	return ips, nil
}

func TestConcurrentCacheAccess(t *testing.T) {
	d := &directDialer{
		dialer:     &net.Dialer{Timeout: 10 * time.Millisecond},
		option:     Option{CacheTTL: 30 * time.Minute},
		dnsCache:   make(map[string]*dnsCacheEntry),
		dnsCacheMu: sync.RWMutex{},
	}

	var wg sync.WaitGroup
	var errorCount atomic.Int32

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			conn, err := d.DialContext(ctx, "tcp", "127.0.0.1:12345")
			if err == nil {
				conn.Close()
			} else {
				errorCount.Add(1)
			}
		}()
	}
	wg.Wait()
	if errorCount.Load() != 20 {
		t.Logf("some connections unexpectedly succeeded: %d errors out of 20", errorCount.Load())
	}
}
