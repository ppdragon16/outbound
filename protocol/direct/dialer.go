package direct

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
)

// Direct is the default direct dialer. It is initialized here so callers
// that use the package without InitDirectDialers (standalone tests, tools)
// get a working zero-option dialer instead of a nil interface that panics on
// first use; InitDirectDialers replaces it with the process-wide options
// (fallback DNS, mptcp, fwmark) during daemon startup.
var Direct netproxy.Dialer = NewDirectDialer(Option{})

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
	// createResolver(mark, "") is the system DNS view, so an unset
	// fallback_resolver must not become a second, identical resolution leg:
	// the field means "the configured fallback resolver" and stays nil without
	// one, whatever the mark is.
	var fallbackResolver *net.Resolver
	if option.FallbackDNS != "" {
		fallbackResolver = createResolver(option.Mark, option.FallbackDNS)
	}
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

// lookupIP resolves host through one resolver. An empty answer is reported as
// an error so a caller racing several resolvers never picks it as the winner.
func lookupIP(ctx context.Context, resolver *net.Resolver, host string) ([]net.IP, error) {
	addrs, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no IP found for domain: %s", host)
	}
	return addrs, nil
}

// resolveLegTimeout bounds each leg of the resolution race on its own, so a
// caller without a deadline and a silently dropping resolver (whose lookups
// retry internally) still gets an answer or a failure instead of hanging; a
// shorter parent deadline wins. It stays above the adapter-level cap in
// resolve.go so the cap, not the leg bound, governs there. (Port of kdae
// 007cdbd8.)
var resolveLegTimeout = 10 * time.Second

// lookupIPBounded is lookupIP with that per-leg bound.
func lookupIPBounded(ctx context.Context, resolver *net.Resolver, host string) ([]net.IP, error) {
	legCtx, cancel := context.WithTimeout(ctx, resolveLegTimeout)
	defer cancel()
	return lookupIP(legCtx, resolver, host)
}

// raceIPLookups resolves host through every resolver concurrently and returns
// the first usable answer. The resolvers are raced instead of tried in order
// because either leg can be blackholed: a sequential preference spends the
// caller's whole resolution budget on the dead leg before the healthy one gets
// a chance, while a race lets whichever leg answers first win.
//
// A losing leg is not awaited, so it cannot delay an answer that is already
// known; it stops on its own because raceCtx is canceled (bounded by the
// resolver's per-attempt deadline) and the buffered channel lets it publish its
// result and exit without a receiver. Failures are joined in resolver order, so
// the system view's diagnosis keeps its position when both legs fail.
func raceIPLookups(ctx context.Context, host string, resolvers []*net.Resolver) ([]net.IP, error) {
	if len(resolvers) == 1 {
		return lookupIPBounded(ctx, resolvers[0], host)
	}

	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	type result struct {
		leg   int
		addrs []net.IP
		err   error
	}
	// Buffered: a loser must be able to publish after the winner returned.
	results := make(chan result, len(resolvers))
	for i, resolver := range resolvers {
		go func(i int, resolver *net.Resolver) {
			addrs, err := lookupIPBounded(raceCtx, resolver, host)
			results <- result{leg: i, addrs: addrs, err: err}
		}(i, resolver)
	}

	errs := make([]error, len(resolvers))
	for range resolvers {
		select {
		case res := <-results:
			if res.err == nil {
				return res.addrs, nil
			}
			errs[res.leg] = res.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, errors.Join(errs...)
}

// splitIPs orders a resolution answer IPv4 first.
func splitIPs(host string, addrs []net.IP) ([]string, error) {
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

// resolveAllIPs resolves host to all IP addresses, preferring IPv4 first. The
// system DNS view and the configured fallback resolver are raced, so a
// blackholed system resolver does not hide a healthy fallback resolver.
func (d *directDialer) resolveAllIPs(ctx context.Context, host string) ([]string, error) {
	systemResolver := d.resolver
	if systemResolver == nil {
		systemResolver = net.DefaultResolver
	}
	resolvers := []*net.Resolver{systemResolver}
	if d.fallbackResolver != nil {
		resolvers = append(resolvers, d.fallbackResolver)
	}

	addrs, err := raceIPLookups(ctx, host, resolvers)
	if err != nil {
		return nil, err
	}
	return splitIPs(host, addrs)
}

// ResolveHost resolves host with the package-level Direct dialer's policy: the
// system DNS view raced with the configured fallback resolver, both carrying
// the dae mark when one is configured. Setup-time code that has to resolve a
// hostname rather than dial it (connectivity-check and DNS-upstream addresses)
// gets the same view of DNS as a dial, instead of an unmarked, system-only
// lookup that dae's own ingress may intercept.
func ResolveHost(ctx context.Context, host string) ([]string, error) {
	d, ok := Direct.(*directDialer)
	if !ok {
		return nil, fmt.Errorf("direct: package-level dialer is %T, not a direct dialer", Direct)
	}
	return d.resolveAllIPs(ctx, host)
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
