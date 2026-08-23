package direct

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/common"
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
	dnsCache         map[string]*dnsCacheEntry // keyed by "host:port"
	dnsCacheMu       sync.RWMutex
}

type dnsCacheEntry struct {
	ips      []string // remaining "ip:port" addrs to try; ips[0] is next
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

// DialContext dials a network address. If the address is a domain name, it
// resolves all IPs and races them concurrently (happy-eyeballs) until one
// succeeds. The winning IP is cached first so subsequent calls prefer it
// (important for mux and for consistency with connectivity checks).
func (d *directDialer) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	if network != "tcp" && network != "udp" {
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// If the host is already an IP, dial directly — no DNS needed.
	if _, err := netip.ParseAddr(host); err == nil {
		return d.dialer.DialContext(ctx, network, addr)
	}

	return d.dialDomain(ctx, network, addr)
}

// dialDomain tries to dial addr (a "host:port" string). Phase 1 races the
// cached IPs; if they all fail the cache is invalidated and Phase 2
// re-resolves DNS.
func (d *directDialer) dialDomain(ctx context.Context, network, addr string) (net.Conn, error) {
	d.dnsCacheMu.RLock()
	entry, ok := d.dnsCache[addr]
	d.dnsCacheMu.RUnlock()

	if ok {
		if time.Now().Before(entry.expireAt) {
			if conn, err := d.tryCachedIPs(ctx, network, addr, entry); err == nil {
				return conn, nil
			}
		}
		d.invalidateCache(addr)
	}
	return d.resolveAndDial(ctx, network, addr)
}

// tryCachedIPs races the cached ip:port addrs concurrently; the winner is
// re-cached first by raceIPs.
func (d *directDialer) tryCachedIPs(ctx context.Context, network, addr string, entry *dnsCacheEntry) (net.Conn, error) {
	return d.raceIPs(ctx, network, addr, entry.ips)
}

// resolveAndDial resolves the host in addr to all IPs and races the dial
// across them.
func (d *directDialer) resolveAndDial(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ips, err := d.resolveAllIPs(ctx, host)
	if err != nil {
		return nil, err
	}
	for i, ip := range ips {
		ips[i] = net.JoinHostPort(ip, port)
	}

	return d.raceIPs(ctx, network, addr, ips)
}

// raceIPs races the TCP/UDP dial across all candidate ip:port addrs
// concurrently (happy-eyeballs) and caches the winner first, so subsequent
// dials of the same addr prefer the previously-working IP (important for mux
// and connectivity-check consistency).
func (d *directDialer) raceIPs(ctx context.Context, network, addr string, ips []string) (net.Conn, error) {
	type dialResult struct {
		conn net.Conn
		addr string
	}
	outcome, err := common.Race(ctx, ips, func(ctx context.Context, s string) (dialResult, error) {
		conn, err := d.dialer.DialContext(ctx, network, s)
		if err != nil {
			return dialResult{}, err
		}
		return dialResult{conn: conn, addr: s}, nil
	}, func(r dialResult) {
		_ = r.conn.Close()
	})
	if err != nil {
		return nil, err
	}

	// Reorder: winner first, then the rest as fallback.
	ordered := make([]string, 0, len(ips))
	ordered = append(ordered, outcome.addr)
	for _, s := range ips {
		if s != outcome.addr {
			ordered = append(ordered, s)
		}
	}
	d.dnsCacheMu.Lock()
	d.dnsCache[addr] = &dnsCacheEntry{
		ips:      ordered,
		expireAt: time.Now().Add(d.option.CacheTTL),
	}
	d.dnsCacheMu.Unlock()

	return outcome.conn, nil
}

// resolveAllIPs resolves host to all IP addresses, preferring IPv4 first.
func (d *directDialer) resolveAllIPs(ctx context.Context, host string) ([]string, error) {
	resolver := d.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addrs, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		if d.fallbackResolver != nil {
			addrs, err = d.fallbackResolver.LookupIP(ctx, "ip", host)
		}
	}
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no IP found for domain: %s", host)
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

// invalidateCache removes the cached entry for addr.
func (d *directDialer) invalidateCache(addr string) {
	d.dnsCacheMu.Lock()
	delete(d.dnsCache, addr)
	d.dnsCacheMu.Unlock()
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
	return &PacketConn{c.(*net.UDPConn)}, nil
}
