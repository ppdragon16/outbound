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

func ResolveIPAddr(address string) (*net.IPAddr, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, err
	}
	return &addrs[0], nil
}

func ResolveUDPAddrWithResolver(resolver *net.Resolver, address string) (*net.UDPAddr, error) {
	host, _port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(_port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", _port)
	}
	addrs, err := resolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, err
	}

	return &net.UDPAddr{
		IP:   addrs[0].IP,
		Zone: addrs[0].Zone,
		Port: int(port),
	}, nil
}

func ResolveTCPAddrWithResolver(resolver *net.Resolver, address string) (*net.TCPAddr, error) {
	host, _port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(_port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", _port)
	}
	addrs, err := resolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, err
	}

	return &net.TCPAddr{
		IP:   addrs[0].IP,
		Zone: addrs[0].Zone,
		Port: int(port),
	}, nil
}

func ResolveUDPAddr(address string) (*net.UDPAddr, error) {
	return ResolveUDPAddrWithResolver(net.DefaultResolver, address)
}

func ResolveTCPAddr(address string) (*net.TCPAddr, error) {
	return ResolveTCPAddrWithResolver(net.DefaultResolver, address)
}
