package direct

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
}

type directDialer struct {
	resolver          *net.Resolver
	tcpDialer         *net.Dialer
	udpDialer         *net.Dialer
	tcpFallbackDialer *net.Dialer
	udpFallbackDialer *net.Dialer
	option            Option
}

// TODO: Cache
func NewDirectDialer(option Option) netproxy.Dialer {
	resolver := createResolver(option.Mark, "")
	fallbackResolver := createResolver(option.Mark, option.FallbackDNS)
	tcpDialer := &net.Dialer{Resolver: resolver}
	udpDialer := &net.Dialer{Resolver: resolver}
	tcpFallbackDialer := &net.Dialer{Resolver: fallbackResolver}
	udpFallbackDialer := &net.Dialer{Resolver: fallbackResolver}
	if option.Mptcp {
		tcpDialer.SetMultipathTCP(true)
		tcpFallbackDialer.SetMultipathTCP(true)
	}
	if option.Mark != 0 {
		control := func(_, _ string, c syscall.RawConn) error {
			return netproxy.SoMarkControl(c, option.Mark)
		}
		tcpDialer.Control = control
		udpDialer.Control = control
		tcpFallbackDialer.Control = control
		udpFallbackDialer.Control = control
	}

	return &directDialer{
		resolver:          resolver,
		tcpDialer:         tcpDialer,
		udpDialer:         udpDialer,
		tcpFallbackDialer: tcpFallbackDialer,
		udpFallbackDialer: udpFallbackDialer,
		option:            option,
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

func (d *directDialer) dialUDP(ctx context.Context, addr string, fallback bool) (net.Conn, error) {
	if fallback {
		return d.udpFallbackDialer.DialContext(ctx, "udp", addr)
	} else {
		return d.udpDialer.DialContext(ctx, "udp", addr)
	}
}

func (d *directDialer) dialTCP(ctx context.Context, addr string, fallback bool) (net.Conn, error) {
	start := time.Now()
	defer func() {
		elapsed := time.Since(start).Seconds()
		DirectDialLatency.Observe(elapsed)
	}()
	if fallback {
		return d.tcpFallbackDialer.DialContext(ctx, "tcp", addr)
	} else {
		return d.tcpDialer.DialContext(ctx, "tcp", addr)
	}
}

func (d *directDialer) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp":
		c, err = d.dialTCP(ctx, addr, false)
		if err != nil && d.shouldRetry(err, addr) {
			c, err = d.dialTCP(ctx, addr, true)
		}
		return
	case "udp":
		c, err = d.dialUDP(ctx, addr, false)
		if err != nil && d.shouldRetry(err, addr) {
			c, err = d.dialUDP(ctx, addr, true)
		}
		return
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
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
	return &PacketConn{c, d.resolver}, nil
}
