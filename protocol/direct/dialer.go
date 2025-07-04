package direct

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/samber/oops"
)

var (
	SymmetricDirect netproxy.Dialer
	FullconeDirect  netproxy.Dialer
)

func InitDirectDialers(fallbackDNS string, mptcp bool) {
	SymmetricDirect = NewDirectDialerLaddr(netip.Addr{}, Option{FullCone: false, FallbackDNS: fallbackDNS, Mptcp: mptcp})
	FullconeDirect = NewDirectDialerLaddr(netip.Addr{}, Option{FullCone: true, FallbackDNS: fallbackDNS, Mptcp: mptcp})
}

type Option struct {
	FullCone    bool
	FallbackDNS string
	Mptcp       bool
}

// udpDialer interface for different UDP dialing strategies
type udpDialer interface {
	dialUDP(ctx context.Context, addr string, mark int, resolver *net.Resolver) (*net.UDPConn, error)
}

// fullconeUDPDialer handles fullcone UDP connections
type fullconeUDPDialer struct {
	localAddr *net.UDPAddr
}

func (f *fullconeUDPDialer) dialUDP(ctx context.Context, addr string, mark int, resolver *net.Resolver) (*net.UDPConn, error) {
	if mark == 0 {
		return net.ListenUDP("udp", f.localAddr)
	}

	// With mark
	config := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return netproxy.SoMarkControl(c, mark)
		},
	}

	laddr := ""
	if f.localAddr != nil {
		laddr = f.localAddr.String()
	}

	conn, err := config.ListenPacket(ctx, "udp", laddr)
	if err != nil {
		return nil, err
	}

	return conn.(*net.UDPConn), nil
}

// symmetricUDPDialer handles symmetric UDP connections
type symmetricUDPDialer struct {
	localAddr *net.UDPAddr
}

func (s *symmetricUDPDialer) dialUDP(ctx context.Context, addr string, mark int, resolver *net.Resolver) (*net.UDPConn, error) {
	dialer := &net.Dialer{
		LocalAddr: s.localAddr,
		Resolver:  resolver,
	}

	if mark != 0 {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			return netproxy.SoMarkControl(c, mark)
		}
	}

	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}

	return conn.(*net.UDPConn), nil
}

type directDialer struct {
	tcpDialer *net.Dialer
	udpDialer udpDialer
	option    Option
}

func NewDirectDialerLaddr(lAddr netip.Addr, option Option) netproxy.Dialer {
	var tcpLocalAddr *net.TCPAddr
	var udpLocalAddr *net.UDPAddr
	if lAddr.IsValid() {
		tcpLocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(lAddr, 0))
		udpLocalAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(lAddr, 0))
	}

	tcpDialer := &net.Dialer{LocalAddr: tcpLocalAddr}
	if option.Mptcp {
		tcpDialer.SetMultipathTCP(true)
	}

	var udpDialer udpDialer
	if option.FullCone {
		udpDialer = &fullconeUDPDialer{localAddr: udpLocalAddr}
	} else {
		udpDialer = &symmetricUDPDialer{localAddr: udpLocalAddr}
	}

	return &directDialer{
		tcpDialer: tcpDialer,
		udpDialer: udpDialer,
		option:    option,
	}
}

func (d *directDialer) shouldRetry(err error, addr string) bool {
	host, _, _ := net.SplitHostPort(addr)
	// Check if the host is domain
	if _, e := netip.ParseAddr(host); e == nil {
		// addr is IP
		return false
	}

	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}

func (d *directDialer) createResolver(mark int, dnsAddress *string) *net.Resolver {
	if mark == 0 && dnsAddress == nil {
		return net.DefaultResolver
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

			if dnsAddress != nil {
				address = *dnsAddress
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
}

func (d *directDialer) dialUdp(ctx context.Context, addr string, mark int, dnsAddress *string) (c netproxy.PacketConn, err error) {
	resolver := d.createResolver(mark, dnsAddress)
	conn, err := d.udpDialer.dialUDP(ctx, addr, mark, resolver)
	if err != nil {
		return nil, oops.
			In("Direct Dialer").
			Wrapf(err, "dialUdp")
	}

	return &directPacketConn{
		UDPConn:  conn,
		FullCone: d.option.FullCone,
		dialTgt:  addr,
		resolver: resolver,
	}, nil
}

func (d *directDialer) dialTcp(ctx context.Context, addr string, mark int, dnsAddress *string) (c net.Conn, err error) {
	if mark != 0 {
		d.tcpDialer.Control = func(network, address string, c syscall.RawConn) error {
			return netproxy.SoMarkControl(c, mark)
		}
	}

	d.tcpDialer.Resolver = d.createResolver(mark, dnsAddress)
	c, err = d.tcpDialer.DialContext(ctx, "tcp", addr)
	return c, oops.
		In("Direct Dialer").
		With("addr", addr).
		With("mark", mark).
		With("dnsAddress", dnsAddress).
		Wrapf(err, "dialTcp")
}

func (d *directDialer) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}

	switch magicNetwork.Network {
	case "tcp":
		c, err = d.dialTcp(ctx, addr, int(magicNetwork.Mark), nil)
		if err != nil && d.shouldRetry(err, addr) {
			c, err = d.dialTcp(ctx, addr, int(magicNetwork.Mark), &d.option.FallbackDNS)
		}
		return c, err
	case "udp":
		c, err = d.dialUdp(ctx, addr, int(magicNetwork.Mark), nil)
		if err != nil && d.shouldRetry(err, addr) {
			c, err = d.dialUdp(ctx, addr, int(magicNetwork.Mark), &d.option.FallbackDNS)
		}
		return c, err
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
