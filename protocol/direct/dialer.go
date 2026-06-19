package direct

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

var (
	Direct netproxy.Dialer
)

func InitDirectDialers(fallbackDNS string, mptcp bool, mark int) {
	Direct = NewDirectDialer(Option{FallbackDNS: fallbackDNS, Mptcp: mptcp, Mark: mark})
}

type Option struct {
	FallbackDNS string
	Mptcp       bool
	Mark        int
	CacheTTL    time.Duration
}

type directDialer struct {
	resolver         *net.Resolver
	fallbackResolver *net.Resolver
	dialer           *net.Dialer
	option           Option
	dnsCache         map[string]*dnsCacheEntry
	dnsCacheMu       sync.RWMutex
}

type dnsCacheEntry struct {
	ip       string
	expireAt time.Time
}

func NewDirectDialer(option Option) netproxy.Dialer {
	if option.CacheTTL == 0 {
		option.CacheTTL = 30 * time.Minute
	}
	resolver := createResolver(option.Mark, "")
	fallbackResolver := createResolver(option.Mark, option.FallbackDNS)
	dialer := &net.Dialer{Resolver: resolver}
	if option.Mptcp {
		dialer.SetMultipathTCP(true)
	}
	if option.Mark != 0 {
		control := func(_, _ string, c syscall.RawConn) error {
			return netproxy.SoMarkControl(c, option.Mark)
		}
		dialer.Control = control
	}

	return &directDialer{
		resolver:         resolver,
		fallbackResolver: fallbackResolver,
		dialer:           dialer,
		option:           option,
		dnsCache:         make(map[string]*dnsCacheEntry),
	}
}

func createResolver(mark int, dnsAddress string) *net.Resolver {
	if mark == 0 && dnsAddress == "" {
		return nil
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{}

			if mark != 0 {
				dialer.Control = func(_, _ string, c syscall.RawConn) error {
					return netproxy.SoMarkControl(c, mark)
				}
			}

			if dnsAddress != "" {
				return dialer.DialContext(ctx, network, dnsAddress)
			} else {
				return dialer.DialContext(ctx, network, address)
			}
		},
	}
}

func (d *directDialer) Alive() bool {
	return true
}

func (d *directDialer) Connect() error {
	return nil
}

func (d *directDialer) Disconnect() error {
	return nil
}

func (d *directDialer) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	if network != "tcp" && network != "udp" {
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
	addr, err = d.resolveAddr(ctx, addr)
	if err != nil {
		return nil, err
	}
	return d.dialer.DialContext(ctx, network, addr)
}

func (d *directDialer) resolveAddr(ctx context.Context, addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}

	// Check if host is already an IP address
	if _, err := netip.ParseAddr(host); err == nil {
		// host is IP, return as-is
		return addr, nil
	}

	// Host is a domain, check cache
	d.dnsCacheMu.RLock()
	entry, ok := d.dnsCache[host]
	d.dnsCacheMu.RUnlock()

	if ok && time.Now().Before(entry.expireAt) {
		// Cache hit
		return net.JoinHostPort(entry.ip, port), nil
	}

	// Cache miss or expired, resolve the domain
	// Try to resolve using the resolver
	addrs, err := d.resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		// Try fallback resolver if main resolver fails
		addrs, err = d.fallbackResolver.LookupIP(ctx, "ip", host)
	}
	if err != nil {
		return "", err
	}

	if len(addrs) == 0 {
		return "", fmt.Errorf("no IP found for domain: %s", host)
	}

	// Use the first IP (prefer IPv4 if available)
	var resolvedIP string
	for _, ip := range addrs {
		if ip4 := ip.To4(); ip4 != nil {
			resolvedIP = ip4.String()
			break
		}
	}
	if resolvedIP == "" {
		resolvedIP = addrs[0].String()
	}

	// Store in cache
	d.dnsCacheMu.Lock()
	d.dnsCache[host] = &dnsCacheEntry{
		ip:       resolvedIP,
		expireAt: time.Now().Add(d.option.CacheTTL),
	}
	d.dnsCacheMu.Unlock()

	return net.JoinHostPort(resolvedIP, port), nil
}

// TODO: Resolver fallback
func (d *directDialer) ListenPacket(ctx context.Context, _ string) (c net.PacketConn, err error) {
	if d.option.Mark == 0 {
		c, err = net.ListenUDP("udp", nil)
	} else {
		// With mark
		config := net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				return netproxy.SoMarkControl(c, d.option.Mark)
			},
		}

		c, err = config.ListenPacket(ctx, "udp", "")
	}
	if err != nil {
		return nil, err
	}
	return &PacketConn{c}, nil
}
