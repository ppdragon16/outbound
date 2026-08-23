/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

// sortIPAddrsIPv4First returns a copy of addrs with IPv4 addresses placed
// before IPv6 addresses, preserving the relative order within each family.
// Cross-border IPv6 is frequently throttled or broken, so IPv4-first gives a
// deterministic order: it makes single-address selection (preferredIPAddr)
// pick IPv4, and keeps the candidate list deterministic for any sequential
// fallback. For concurrent racing the order itself is irrelevant (all
// candidates start at once).
func sortIPAddrsIPv4First(addrs []net.IPAddr) []net.IPAddr {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]net.IPAddr, 0, len(addrs))
	for i := range addrs {
		if addrs[i].IP.To4() != nil {
			out = append(out, addrs[i])
		}
	}
	for i := range addrs {
		if addrs[i].IP.To4() == nil {
			out = append(out, addrs[i])
		}
	}
	return out
}

// preferredIPAddr returns the preferred address from addrs: IPv4 first, then
// IPv6. IPv6-only hosts are unaffected — we fall back to the first IPv6
// address. Returns nil when addrs is empty.
func preferredIPAddr(addrs []net.IPAddr) *net.IPAddr {
	sorted := sortIPAddrsIPv4First(addrs)
	if len(sorted) == 0 {
		return nil
	}
	return &sorted[0]
}

func ResolveIPAddrWithResolver(resolver *net.Resolver, address string) (*net.IPAddr, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	addrs, err := resolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, err
	}
	addr := preferredIPAddr(addrs)
	if addr == nil {
		return nil, fmt.Errorf("no IP address found for %s", host)
	}
	return addr, nil
}

// ResolveIPAddrsWithResolver resolves address to all of its IP addresses,
// sorted IPv4-first. Unlike ResolveIPAddrWithResolver it returns the full
// candidate list so callers can race them (happy-eyeballs) instead of pinning
// to a single address.
func ResolveIPAddrsWithResolver(resolver *net.Resolver, address string) ([]net.IPAddr, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	addrs, err := resolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, err
	}
	return sortIPAddrsIPv4First(addrs), nil
}

func ResolveIPAddrs(address string) ([]net.IPAddr, error) {
	return ResolveIPAddrsWithResolver(net.DefaultResolver, address)
}

// ResolveUDPAddrs resolves address (host:port) to all of its IPs as UDP
// addresses, sorted IPv4-first. Used for happy-eyeballs racing of a
// single-port dialer.
func ResolveUDPAddrs(address string) ([]net.Addr, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", portStr)
	}
	ips, err := ResolveIPAddrs(host)
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

func resolveIPAddrWithResolver(resolver *net.Resolver, address string) (*net.IPAddr, int, error) {
	host, _port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, 0, err
	}
	port, err := strconv.ParseUint(_port, 10, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid port: %v", _port)
	}
	addrs, err := resolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, 0, err
	}
	addr := preferredIPAddr(addrs)
	if addr == nil {
		return nil, 0, fmt.Errorf("no IP address found for %s", host)
	}

	return addr, int(port), nil
}

func ResolveUDPAddrWithResolver(resolver *net.Resolver, address string) (*net.UDPAddr, error) {
	addr, port, err := resolveIPAddrWithResolver(resolver, address)
	if err != nil {
		return nil, err
	}

	return &net.UDPAddr{
		IP:   addr.IP,
		Zone: addr.Zone,
		Port: port,
	}, nil
}

func ResolveTCPAddrWithResolver(resolver *net.Resolver, address string) (*net.TCPAddr, error) {
	addr, port, err := resolveIPAddrWithResolver(resolver, address)
	if err != nil {
		return nil, err
	}

	return &net.TCPAddr{
		IP:   addr.IP,
		Zone: addr.Zone,
		Port: port,
	}, nil
}

func ResolveIPAddr(address string) (*net.IPAddr, error) {
	return ResolveIPAddrWithResolver(net.DefaultResolver, address)
}

func ResolveUDPAddr(address string) (*net.UDPAddr, error) {
	return ResolveUDPAddrWithResolver(net.DefaultResolver, address)
}

func ResolveTCPAddr(address string) (*net.TCPAddr, error) {
	return ResolveTCPAddrWithResolver(net.DefaultResolver, address)
}
