// Package server implements a reference MASQUE proxy server (RFC 9298
// CONNECT-UDP + plain HTTP/3 CONNECT) on top of the http3 stack that
// outbound's masque client targets. It exists because no mainstream proxy
// core ships a masque *server* (sing-box/xray: none; mihomo: client only;
// Cloudflare WARP: token-bound), so self-hosting is the practical route.
//
// Protocol coverage matches protocol/masque's client:
//   - TCP: plain HTTP/3 CONNECT, :authority carries the target, raw bytes on
//     the stream after a 2xx response;
//   - UDP: extended CONNECT ("connect-udp") to
//     /.well-known/masque/udp/{host}/{port}/ (RFC 9298 section 3.2), payloads
//     as RFC 9297 HTTP datagrams with context id 0.
//
// The protocol has no authentication: gate callers at the network layer or
// via Config.AllowTarget.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	quic "github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"

	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion"
	"github.com/daeuniverse/quic-go/quicvarint"
	utls "github.com/refraction-networking/utls"
)

const (
	connectUDPProtocol = "connect-udp"
	udpPathPrefix      = "/.well-known/masque/udp/"

	defaultIdleTimeout = 5 * time.Minute
	dialTimeout        = 10 * time.Second
)

// Config customizes the server.
type Config struct {
	// Certificate is the TLS leaf served to clients. Serve requires it.
	Certificate utls.Certificate
	// IdleTimeout caps how long a UDP flow may stay silent before its relay
	// is torn down. Defaults to 5 minutes (the client's MaxIdleTimeout).
	IdleTimeout time.Duration
	// AllowTarget, when non-nil, gates every proxy target; returning an
	// error rejects the request with 403. Without it every target is
	// allowed - an open relay.
	AllowTarget func(network string, addr netip.AddrPort) error
	// Logger receives per-connection warnings; nil logging is fine.
	Logger *slog.Logger
	// CongestionControl selects the relay's congestion controller for the
	// send direction (the client's download): "bbrv3" (default) or "bbr"
	// (BBRv1). Long-RTT or lossy paths sometimes do better on BBRv1.
	CongestionControl string
	// InitialPacketSize sets the QUIC Initial packet size (path MTU budget) of
	// the server's connections. Zero keeps the safe protocol default (1280); a
	// larger value (e.g. 1452 on a 1500-MTU path) lets the relay carry the full
	// datagram budget from the first packet, but breaks the handshake with
	// clients whose path MTU cannot carry it.
	InitialPacketSize int
	// ConnContext, when set, is called with each accepted QUIC connection,
	// mirroring http3.Server.ConnContext. Use it to tag request contexts with
	// connection state (e.g. for metrics).
	ConnContext func(ctx context.Context, c quic.Connection) context.Context
}

// Server is a masque proxy server. Create one with New, then Serve it on a
// UDP packet conn.
type Server struct {
	conf Config
	log  *slog.Logger
	h3   *http3.Server

	ctx    context.Context
	cancel context.CancelFunc
}

// New wraps the config into a ready-to-serve server.
func New(conf Config) (*Server, error) {
	if conf.IdleTimeout <= 0 {
		conf.IdleTimeout = defaultIdleTimeout
	}
	if conf.Logger == nil {
		conf.Logger = slog.New(slog.DiscardHandler)
	}
	// Mirror the client's transport tuning: the relay carries whatever the
	// peer sends, and the default cubic controller plus small windows cap a
	// long-RTT path far below the line rate.
	quicConf := &quic.Config{
		Allow0RTT:                      true,
		InitialCongestionControl:       congestion.NewInitialSender(conf.CongestionControl, nil),
		InitialStreamReceiveWindow:     common.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         common.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: common.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     common.MaxConnectionReceiveWindow,
		KeepAlivePeriod:                10 * time.Second,
	}
	if conf.InitialPacketSize > 0 {
		quicConf.InitialPacketSize = uint16(conf.InitialPacketSize)
	}
	s := &Server{conf: conf, log: conf.Logger}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.h3 = &http3.Server{
		Handler:    s,
		QUICConfig: quicConf,
		// EnableDatagrams is what the client's CONNECT-UDP datagrams ride
		// on; without it ReceiveDatagram/SendDatagram fail.
		EnableDatagrams: true,
		TLSConfig: &utls.Config{
			Certificates: []utls.Certificate{conf.Certificate},
		},
		ConnContext: conf.ConnContext,
		// QUICConfig stays nil on purpose: http3.Server then defaults to
		// Allow0RTT: true, which the client's zero_rtt option relies on.
	}
	return s, nil
}

// Serve accepts QUIC connections on pc until Close is called.
func (s *Server) Serve(pc net.PacketConn) error { return s.h3.Serve(pc) }

// Close shuts the server down and unblocks every relay handler.
func (s *Server) Close() error {
	s.cancel()
	return s.h3.Close()
}

// ServeHTTP dispatches one request stream: plain CONNECT relays TCP,
// extended CONNECT relays UDP datagrams.
//
// The request stream is hijacked only after every check has passed and the
// success status is committed: http3's HTTPStream() flushes, which commits a
// default 200 OK when no status was written yet, and a later WriteHeader is
// then a no-op - validating after hijacking would silently turn rejections
// into successful CONNECTs.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Proto == connectUDPProtocol {
		s.serveUDP(w, r)
		return
	}
	s.serveTCP(w, r)
}

// hijackStream commits a 200 response and takes over the raw stream. Call it
// only once the request is known to be servable.
func hijackStream(w http.ResponseWriter) (http3.Stream, bool) {
	hijacker, ok := w.(http3.HTTPStreamer)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return nil, false
	}
	w.WriteHeader(http.StatusOK)
	str, ok := hijacker.HTTPStream().(http3.Stream)
	if !ok {
		return nil, false
	}
	return str, true
}

// serveTCP relays a plain CONNECT as a raw TCP tunnel.
func (s *Server) serveTCP(w http.ResponseWriter, r *http.Request) {
	target, err := parseTarget("tcp", r.Host, s.conf.AllowTarget)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		s.log.Warn("tcp target rejected", "target", r.Host, "err", err)
		return
	}
	up, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		s.log.Warn("tcp dial failed", "target", target, "err", err)
		return
	}
	defer up.Close()

	str, ok := hijackStream(w)
	if !ok {
		return
	}

	// Client half-close (a FIN on the stream) must become a TCP FIN, and a
	// TCP FIN must finish the stream - otherwise either side lingers until
	// the idle timeout.
	go func() {
		_, _ = io.Copy(up, str)
		if tc, isTCP := up.(*net.TCPConn); isTCP {
			_ = tc.CloseWrite()
		}
	}()
	_, _ = io.Copy(str, up)
	// The upstream finished (or died): send the client a FIN instead of
	// letting its stream hang until the QUIC idle timeout.
	_ = str.Close()
}

// serveUDP relays an extended CONNECT-UDP flow as datagrams to one target.
func (s *Server) serveUDP(w http.ResponseWriter, r *http.Request) {
	target, err := parseUDPPath(r.URL.Path)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		s.log.Warn("udp path rejected", "path", r.URL.Path, "err", err)
		return
	}
	addr, err := parseTarget("udp", target, s.conf.AllowTarget)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		s.log.Warn("udp target rejected", "target", target, "err", err)
		return
	}
	up, err := net.DialTimeout("udp", addr, dialTimeout)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		s.log.Warn("udp dial failed", "target", addr, "err", err)
		return
	}
	defer up.Close()

	w.Header().Set("Capsule-Protocol", "?1")
	str, ok := hijackStream(w)
	if !ok {
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Client -> target: HTTP datagrams carry a context id (0) prefix.
	go func() {
		for {
			buf, err := str.ReceiveDatagram(ctx)
			if err != nil {
				cancel()
				return
			}
			contextID, consumed, err := quicvarint.Parse(buf)
			if err != nil || contextID != 0 {
				// Unknown context: RFC 9298 says drop, not fail.
				continue
			}
			if _, err := up.Write(buf[consumed:]); err != nil {
				cancel()
				return
			}
		}
	}()

	// Target -> client. The socket read is bounded so Close can unblock it;
	// idleTimeout is enforced by tracking the last activity time.
	lastActive := time.Now()
	buf := make([]byte, 65536)
	for {
		if err := up.SetReadDeadline(time.Now().Add(udpPollInterval)); err != nil {
			return
		}
		n, err := up.Read(buf)
		if n > 0 {
			lastActive = time.Now()
			dgram := append(quicvarint.Append(nil, 0), buf[:n]...)
			if err := str.SendDatagram(dgram); err != nil {
				return
			}
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				select {
				case <-s.ctx.Done():
					return
				default:
				}
				if time.Since(lastActive) > s.conf.IdleTimeout {
					return
				}
				continue
			}
			return
		}
	}
}

// udpPollInterval bounds how long a relay's socket read can delay shutdown.
const udpPollInterval = 250 * time.Millisecond

// parseTarget validates and normalizes a proxy target against the gate.
func parseTarget(network, addr string, allow func(string, netip.AddrPort) error) (string, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("target needs host:port: %w", err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", fmt.Errorf("invalid port %q", portStr)
	}
	ap := netip.AddrPort{}
	if ip, err := netip.ParseAddr(host); err == nil {
		ap = netip.AddrPortFrom(ip.Unmap(), uint16(port))
	}
	if allow != nil {
		if err := allow(network, ap); err != nil {
			return "", err
		}
	}
	return net.JoinHostPort(host, portStr), nil
}

// parseUDPPath decodes the RFC 9298 CONNECT-UDP path the client builds:
// /well-known/masque/udp/{percent-escaped host}/{port}/. The host keeps its
// colons escaped as %3A by the client, so it is unescaped here.
func parseUDPPath(path string) (string, error) {
	rest := strings.TrimPrefix(path, udpPathPrefix)
	rest = strings.TrimSuffix(rest, "/")
	sep := strings.LastIndex(rest, "/")
	if sep <= 0 || sep == len(rest)-1 {
		return "", errors.New("malformed CONNECT-UDP path")
	}
	host, err := url.PathUnescape(rest[:sep])
	if err != nil {
		return "", fmt.Errorf("unescape host: %w", err)
	}
	port := rest[sep+1:]
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", fmt.Errorf("invalid port %q", port)
	}
	return net.JoinHostPort(host, port), nil
}
