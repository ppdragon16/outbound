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

func ResolveIPAddrWithResolver(resolver *net.Resolver, address string) (*net.IPAddr, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	addrs, err := resolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, err
	}
	return &addrs[0], nil
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

	return &addrs[0], int(port), nil
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
