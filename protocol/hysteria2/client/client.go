package client

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/samber/oops"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/utils"
	"github.com/daeuniverse/outbound/protocol/hysteria2/udphop"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion"

	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

const (
	closeErrCodeOK            = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError
)

type Client interface {
	TCP(addr string, ctx context.Context) (netproxy.Conn, error)
	UDP(addr string, ctx context.Context) (netproxy.Conn, error)
}

type HandshakeInfo struct {
	UDPEnabled bool
	Tx         uint64 // 0 if using BBR
}

func NewClient(config *Config) (Client, error) {
	if err := config.verifyAndFill(); err != nil {
		return nil, err
	}
	c := &clientImpl{
		config: config,
	}
	return c, nil
}

// TODO: 同一个 dialer 不同 mark 如何处理 quic conn?

type clientImpl struct {
	config *Config

	pktConn net.PacketConn
	conn    quic.Connection

	udpSM *udpSessionManager

	m sync.Mutex
}

func (c *clientImpl) connect(parent context.Context) (*HandshakeInfo, error) {
	ctx, cancel := netproxy.NewDialTimeoutContextFrom(parent)
	defer cancel()

	var pktConn net.PacketConn
	var err error

	if c.config.Addr.Network() == "udphop" {
		if err != nil {
			return nil, err
		}
		dialFunc := func(addr net.Addr) (net.PacketConn, error) {
			conn, err := c.config.NextDialer.DialContext(ctx, "udp", addr.String())
			if err != nil {
				return nil, err
			}
			pktConn = netproxy.NewFakeNetPacketConn(
				conn.(netproxy.PacketConn),
				net.UDPAddrFromAddrPort(common.GetUniqueFakeAddrPort()),
				addr,
			)
			return pktConn, nil
		}
		pktConn, err = udphop.NewUDPHopPacketConn(c.config.Addr.(*udphop.UDPHopAddr), c.config.UDPHopInterval, dialFunc)
		if err != nil {
			return nil, err
		}
	} else {
		if err != nil {
			return nil, err
		}
		conn, err := c.config.NextDialer.DialContext(ctx, "udp", c.config.ProxyAddress)
		if err != nil {
			return nil, err
		}
		pktConn = netproxy.NewFakeNetPacketConn(
			conn.(netproxy.PacketConn),
			net.UDPAddrFromAddrPort(common.GetUniqueFakeAddrPort()),
			c.config.Addr,
		)
	}

	// Convert config to TLS config & QUIC config
	tlsConfig := &tls.Config{
		ServerName:            c.config.TLSConfig.ServerName,
		InsecureSkipVerify:    c.config.TLSConfig.InsecureSkipVerify,
		VerifyPeerCertificate: c.config.TLSConfig.VerifyPeerCertificate,
		RootCAs:               c.config.TLSConfig.RootCAs,
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     c.config.QUICConfig.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.config.QUICConfig.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.config.QUICConfig.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.config.QUICConfig.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.config.QUICConfig.MaxIdleTimeout,
		KeepAlivePeriod:                c.config.QUICConfig.KeepAlivePeriod,
		DisablePathMTUDiscovery:        c.config.QUICConfig.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
	}
	// Prepare Transport
	var conn quic.EarlyConnection
	rt := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			qc, err := quic.DialEarly(ctx, pktConn, c.config.Addr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			conn = qc
			return qc, nil
		},
	}
	// Send auth HTTP request
	u := &url.URL{
		Scheme: "https",
		Host:   protocol.URLHost,
		Path:   protocol.URLPath,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return nil, oops.
			In("HTTP3 handshake").
			WithContext(ctx).
			Wrapf(err, "failed to create HTTP request")
	}
	req.Header = make(http.Header)
	protocol.AuthRequestToHeader(req.Header, protocol.AuthRequest{
		Auth: c.config.Auth,
		Rx:   c.config.BandwidthConfig.MaxRx,
	})
	resp, err := rt.RoundTrip(req)
	if err != nil {
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = pktConn.Close()
		return nil, oops.In("HTTP3 Handshake").Wrapf(err, "failed to make HTTP request")
	}
	if resp.StatusCode != protocol.StatusAuthOK {
		_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		_ = pktConn.Close()
		return nil, oops.In("HTTP3 Handshake").Wrapf(err, "authentication error, HTTP status code: %v", resp.StatusCode)
	}
	// Auth OK
	authResp := protocol.AuthResponseFromHeader(resp.Header)
	var actualTx uint64
	if authResp.RxAuto {
		// Server asks client to use bandwidth detection,
		// ignore local bandwidth config and use BBR
		congestion.UseBBR(conn)
	} else {
		// actualTx = min(serverRx, clientTx)
		actualTx = authResp.Rx
		if actualTx == 0 || actualTx > c.config.BandwidthConfig.MaxTx {
			// Server doesn't have a limit, or our clientTx is smaller than serverRx
			actualTx = c.config.BandwidthConfig.MaxTx
		}
		if actualTx > 0 {
			congestion.UseBrutal(conn, actualTx)
		} else {
			// We don't know our own bandwidth either, use BBR
			congestion.UseBBR(conn)
		}
	}
	_ = resp.Body.Close()

	if c.conn != nil {
		c.conn.CloseWithError(closeErrCodeProtocolError, "")
	}
	if c.pktConn != nil {
		c.pktConn.Close()
	}
	if c.udpSM != nil {
		c.udpSM.Close()
	}

	c.pktConn = pktConn
	c.conn = conn
	if authResp.UDPEnabled {
		c.udpSM = newUDPSessionManager(&udpIOImpl{Conn: conn})
	}
	return &HandshakeInfo{
		UDPEnabled: authResp.UDPEnabled,
		Tx:         actualTx,
	}, nil
}

func (c *clientImpl) connected() bool {
	if c.conn == nil {
		return false
	}
	if c.conn.Context().Err() != nil {
		return false
	}
	if c.udpSM != nil && c.udpSM.ctx.Err() != nil {
		return false
	}
	return true
}

func prepareConn(c *clientImpl, ctx context.Context) error {
	c.m.Lock()
	defer c.m.Unlock()
	if ctx.Err() != nil { // If context is already close while waiting for the lock, close the connection
		return ctx.Err()
	}
	if !c.connected() {
		if _, err := c.connect(ctx); err != nil {
			return err
		}
	}
	return nil
}

// openStream wraps the stream with QStream, which handles Close() properly
func (c *clientImpl) openStream() (*utils.QStream, error) {
	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &utils.QStream{Stream: stream}, nil
}

func (c *clientImpl) TCP(addr string, ctx context.Context) (netproxy.Conn, error) {
	err := prepareConn(c, ctx)
	if err != nil {
		return nil, err
	}
	stream, err := c.openStream()
	if err != nil {
		if _, ok := err.(quic.StreamLimitReachedError); !ok {
			c.close()
		}
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		stream.SetDeadline(deadline)
		defer stream.SetDeadline(time.Time{})
	}
	// Send requestd
	err = protocol.WriteTCPRequest(stream, addr)
	if err != nil {
		stream.Close()
		return nil, err
	}
	if c.config.FastOpen {
		// Don't wait for the response when fast open is enabled.
		// Return the connection immediately, defer the response handling
		// to the first Read() call.
		return &tcpConn{
			Orig:             stream,
			PseudoLocalAddr:  c.conn.LocalAddr(),
			PseudoRemoteAddr: c.conn.RemoteAddr(),
			Established:      false,
		}, nil
	}
	// Read response
	ok, msg, err := protocol.ReadTCPResponse(stream)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if !ok {
		_ = stream.Close()
		return nil, oops.In("TCP Dial").Wrapf(err, "from remote: %v", msg)
	}
	return &tcpConn{
		Orig:             stream,
		PseudoLocalAddr:  c.conn.LocalAddr(),
		PseudoRemoteAddr: c.conn.RemoteAddr(),
		Established:      true,
	}, nil
}

func (c *clientImpl) UDP(addr string, ctx context.Context) (netproxy.Conn, error) {
	err := prepareConn(c, ctx)
	if err != nil {
		return nil, oops.In("UDP Dial").Wrap(err)
	}
	if c.udpSM == nil {
		return nil, oops.In("UDP Dial").New("UDP not enabled")
	}
	return c.udpSM.NewUDP(addr)
}

func (c *clientImpl) close() {
	if c.conn != nil {
		c.conn.CloseWithError(closeErrCodeProtocolError, "")
	}
	c.pktConn.Close()
}

type tcpConn struct {
	Orig             *utils.QStream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr
	Established      bool
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	if !c.Established {
		// Read response
		ok, msg, err := protocol.ReadTCPResponse(c.Orig)
		if err != nil {
			return 0, oops.In("TCP Conn").Wrap(err)
		}
		if !ok {
			return 0, oops.In("TCP Conn").Wrapf(err, msg)
		}
		c.Established = true
	}
	n, err = c.Orig.Read(b)
	return n, oops.In("TCP Conn").Wrap(err)
}

func (c *tcpConn) Write(b []byte) (n int, err error) {
	n, err = c.Orig.Write(b)
	return n, oops.In("TCP Conn").Wrap(err)
}

func (c *tcpConn) Close() error {
	err := c.Orig.Close()
	return oops.In("TCP Conn").Wrap(err)
}

func (c *tcpConn) CloseWrite() error {
	// quic-go's default close only closes the write side
	// for more info, see comments in utils.QStream struct
	err := c.Orig.Stream.Close()
	return oops.In("TCP Conn").Wrap(err)
}

func (c *tcpConn) CloseRead() error {
	c.Orig.Stream.CancelRead(0)
	return nil
}

func (c *tcpConn) LocalAddr() net.Addr {
	return c.PseudoLocalAddr
}

func (c *tcpConn) RemoteAddr() net.Addr {
	return c.PseudoRemoteAddr
}

func (c *tcpConn) SetDeadline(t time.Time) error {
	err := c.Orig.SetDeadline(t)
	return oops.In("TCP Conn").Wrap(err)
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	err := c.Orig.SetReadDeadline(t)
	return oops.In("TCP Conn").Wrap(err)
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	err := c.Orig.SetWriteDeadline(t)
	return oops.In("TCP Conn").Wrap(err)
}

type udpIOImpl struct {
	Conn quic.Connection
}

func (io *udpIOImpl) ReceiveMessage(ctx context.Context) (*protocol.UDPMessage, error) {
	for {
		msg, err := io.Conn.ReceiveDatagram(ctx)
		if err != nil {
			// Connection error, this will stop the session manager
			return nil, oops.In("UDP IO").Wrapf(err, "ReceiveMessage")
		}
		udpMsg, err := protocol.ParseUDPMessage(msg)
		if err != nil {
			// Invalid message, this is fine - just wait for the next
			continue
		}
		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		// Message larger than buffer, silent drop
		return nil
	}
	err := io.Conn.SendDatagram(buf[:msgN])
	return oops.In("UDP IO").Wrapf(err, "SendMessage")
}
