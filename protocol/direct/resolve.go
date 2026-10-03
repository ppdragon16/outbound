package direct

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// resolveAddrTimeout bounds a policy lookup for callers that cannot pass a
// context of their own: protocol dialers resolve their server address while the
// dialer set is being built, so an unreachable DNS server must fail that lookup
// instead of stalling the caller. It is a variable only so tests can shorten it.
var resolveAddrTimeout = 5 * time.Second

// The Resolve* helpers below apply the same policy as a dial: the system DNS
// view raced against the configured fallback resolver, both carrying the dae
// mark, IPv4 first. Protocols that must resolve their server address before
// they can dial it (the QUIC ones, whose transport targets are addresses and
// not names) therefore resolve it the way the rest of the daemon does, instead
// of an unmarked, system-only lookup that dae's own ingress may intercept.
// Targets of a proxied connection are a different question and must not use
// this: they follow the routing rules, not the node's direct policy.

// ResolveIPAddrs resolves address -- a hostname, or "host:port" whose port is
// ignored -- to all of its addresses, IPv4 first.
func ResolveIPAddrs(address string) ([]net.IPAddr, error) {
	return resolveIPAddrsWithTimeout(context.Background(), address)
}

// ResolveIPAddrsContext is ResolveIPAddrs with the caller's context. The lookup
// is additionally capped by resolveAddrTimeout, so a caller without a deadline
// still cannot stall on an unreachable DNS server.
func ResolveIPAddrsContext(ctx context.Context, address string) ([]net.IPAddr, error) {
	return resolveIPAddrsWithTimeout(ctx, address)
}

// ResolveIPAddr resolves address to a single address, IPv4 first.
func ResolveIPAddr(address string) (*net.IPAddr, error) {
	addrs, err := ResolveIPAddrs(address)
	if err != nil {
		return nil, err
	}
	return &addrs[0], nil
}

// ResolveUDPAddrs resolves address (host:port) to all of its addresses as UDP
// addresses, IPv4 first. The port is preserved for every candidate.
func ResolveUDPAddrs(address string) ([]net.Addr, error) {
	return resolveUDPAddrsWithTimeout(context.Background(), address)
}

// ResolveUDPAddrsContext is ResolveUDPAddrs with the caller's context.
func ResolveUDPAddrsContext(ctx context.Context, address string) ([]net.Addr, error) {
	return resolveUDPAddrsWithTimeout(ctx, address)
}

// ResolveUDPAddr resolves address (host:port) to a single UDP address, IPv4
// first.
func ResolveUDPAddr(address string) (*net.UDPAddr, error) {
	addrs, err := ResolveUDPAddrs(address)
	if err != nil {
		return nil, err
	}
	return addrs[0].(*net.UDPAddr), nil
}

// resolveIPAddrsWithTimeout resolves address through the policy. An address
// literal never needs a lookup, which keeps a direct-IP configuration free of
// DNS and of the mark that a lookup would carry.
func resolveIPAddrsWithTimeout(ctx context.Context, address string) ([]net.IPAddr, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// No port to strip (mirrors common.ResolveIPAddrs).
		host = address
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return []net.IPAddr{{IP: net.IP(addr.AsSlice()), Zone: addr.Zone()}}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, resolveAddrTimeout)
	defer cancel()
	ips, err := ResolveHost(ctx, host)
	if err != nil {
		return nil, err
	}
	addrs := make([]net.IPAddr, 0, len(ips))
	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		addrs = append(addrs, net.IPAddr{IP: net.IP(addr.AsSlice()), Zone: addr.Zone()})
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no IP address found for %s", host)
	}
	return addrs, nil
}

func resolveUDPAddrsWithTimeout(ctx context.Context, address string) ([]net.Addr, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", portStr)
	}
	ips, err := resolveIPAddrsWithTimeout(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.Addr, 0, len(ips))
	for i := range ips {
		out = append(out, &net.UDPAddr{
			IP:   ips[i].IP,
			Zone: ips[i].Zone,
			Port: int(port),
		})
	}
	return out, nil
}
