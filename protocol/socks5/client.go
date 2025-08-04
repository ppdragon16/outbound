// Modified from https://github.com/nadoo/glider/tree/v0.16.2

package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

// NewSocks5Dialer returns a socks5 proxy netproxy.
func NewSocks5Dialer(s string, d netproxy.Dialer) (netproxy.Dialer, error) {
	return NewSocks5(s, d)
}

func (s *Socks5) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp":
		c, err := s.dialer.DialContext(ctx, "tcp", s.addr)
		if err != nil {
			return nil, fmt.Errorf("[socks5]: dial to %s error: %w", s.addr, err)
		}
		_, err = common.Invoke(ctx, func() (socks.Addr, error) {
			return s.connect(c, address, socks.CmdConnect)
		}, func() {
			c.Close()
		})
		return c, err
	case "udp":
		c, err := s.ListenPacket(ctx, address)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{
			PacketConn: c,
			Address:    netproxy.NewProxyAddr("udp", address),
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *Socks5) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	ctrlConn, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("[socks5]: dial to %s error: %w", s.addr, err)
	}
	// Get the proxy addr we should dial.
	// TODO: target should be laddr of udp conn
	uAddr, err := common.Invoke(ctx, func() (socks.Addr, error) {
		return s.connect(ctrlConn, addr, socks.CmdUDPAssociate)
	}, func() {
		ctrlConn.Close()
	})
	if err != nil {
		return nil, err
	}

	buf := pool.GetBuffer(socks.MaxAddrLen)
	defer pool.PutBuffer(buf)

	uAddress := uAddr.String()
	h, p, err := net.SplitHostPort(uAddress)
	if err != nil {
		return nil, fmt.Errorf("[socks5] invalid bind address: %w", err)
	}
	// if returned bind ip is unspecified
	if h == "" {
		// indicate using conventional addr
		h, _, _ = net.SplitHostPort(s.addr)
		uAddress = net.JoinHostPort(h, p)
	}

	conn, err := s.dialer.ListenPacket(ctx, uAddress)
	if err != nil {
		return nil, fmt.Errorf("[socks5] dialudp to %s error: %w", uAddress, err)
	}

	return NewPktConn(conn, ctrlConn, netproxy.NewProxyAddr("udp", uAddress)), nil
}

// connect takes an existing connection to a socks5 proxy server,
// and commands the server to extend that connection to target,
// which must be a canonical address with a host and port.
func (s *Socks5) connect(conn net.Conn, target string, cmd byte) (addr socks.Addr, err error) {
	// the size here is just an estimate
	buf := pool.GetBuffer(socks.MaxAddrLen)
	defer pool.PutBuffer(buf)

	buf = append(buf[:0], Version)
	if len(s.user) > 0 && len(s.user) < 256 && len(s.password) < 256 {
		buf = append(buf, 2 /* num auth methods */, socks.AuthNone, socks.AuthPassword)
	} else {
		buf = append(buf, 1 /* num auth methods */, socks.AuthNone)
	}

	if _, err := conn.Write(buf); err != nil {
		return addr, errors.New("proxy: failed to write greeting to SOCKS5 proxy at " + s.addr + ": " + err.Error())
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return addr, errors.New("proxy: failed to read greeting from SOCKS5 proxy at " + s.addr + ": " + err.Error())
	}
	if buf[0] != Version {
		return addr, errors.New("proxy: SOCKS5 proxy at " + s.addr + " has unexpected version " + strconv.Itoa(int(buf[0])))
	}
	if buf[1] == 0xff {
		return addr, errors.New("proxy: SOCKS5 proxy at " + s.addr + " requires authentication")
	}

	if buf[1] == socks.AuthPassword {
		buf = buf[:0]
		buf = append(buf, 1 /* password protocol version */)
		buf = append(buf, uint8(len(s.user)))
		buf = append(buf, s.user...)
		buf = append(buf, uint8(len(s.password)))
		buf = append(buf, s.password...)

		if _, err := conn.Write(buf); err != nil {
			return addr, errors.New("proxy: failed to write authentication request to SOCKS5 proxy at " + s.addr + ": " + err.Error())
		}

		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			return addr, errors.New("proxy: failed to read authentication reply from SOCKS5 proxy at " + s.addr + ": " + err.Error())
		}

		if buf[1] != 0 {
			return addr, errors.New("proxy: SOCKS5 proxy at " + s.addr + " rejected username/password")
		}
	}

	buf = buf[:0]
	buf = append(buf, Version, cmd, 0 /* reserved */)
	tgtAddr, err := socks.ParseAddr(target)
	if err != nil {
		return nil, err
	}
	buf = append(buf, tgtAddr...)

	if _, err := conn.Write(buf); err != nil {
		return addr, errors.New("proxy: failed to write connect request to SOCKS5 proxy at " + s.addr + ": " + err.Error())
	}

	// read VER REP RSV
	if _, err := io.ReadFull(conn, buf[:3]); err != nil {
		return addr, errors.New("proxy: failed to read connect reply from SOCKS5 proxy at " + s.addr + ": " + err.Error())
	}

	failure := "unknown error"
	if int(buf[1]) < len(socks.Errors) {
		failure = socks.Errors[buf[1]].Error()
		if strings.Contains(failure, "command not supported") {
			failure += " by socks5 server: " + socks.Command[cmd]
		}
	}

	if len(failure) > 0 {
		return addr, errors.New("proxy: SOCKS5 proxy at " + s.addr + " failed to connect: " + failure)
	}

	return socks.ReadAddr(conn)
}
