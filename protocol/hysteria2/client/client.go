package client

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/samber/oops"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/utils"
	"github.com/daeuniverse/outbound/protocol/hysteria2/udphop"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion"

	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

const (
	closeErrCodeOK            = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError
)

type HandshakeInfo struct {
	UDPEnabled bool
	Tx         uint64 // 0 if using BBR
}

type Client struct {
	config *Config

	pktConn net.PacketConn
	conn    quic.Connection
	udpSM   *udpSessionManager

	m sync.Mutex
}

func NewClient(config *Config) (*Client, error) {
	if err := config.verifyAndFill(); err != nil {
		return nil, err
	}
	c := &Client{
		config: config,
	}
	return c, nil
}

func (c *Client) connect(parent context.Context) (*HandshakeInfo, error) {
	ctx, cancel := netproxy.NewDialTimeoutContextFrom(parent)
	defer cancel()

	var err error
	defer func() {
		if err != nil {
			c.close()
		}
	}()

	if c.config.Addr.Network() == "udphop" {
		// NextDialer.ListenPacket have to get a new lAddr every time.
		// Otherwise port hopping will not work.
		dialFunc := func(addr net.Addr) (net.Conn, error) {
			return c.config.NextDialer.DialContext(ctx, "udp", addr.String())
		}
		c.pktConn, err = udphop.NewUDPHopPacketConn(c.config.Addr.(*udphop.UDPHopAddr), c.config.UDPHopInterval, dialFunc)
		if err != nil {
			return nil, err
		}
	} else {
		c.pktConn, err = c.config.NextDialer.ListenPacket(ctx, c.config.Addr.String())
		if err != nil {
			return nil, err
		}
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
	rt := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			qc, err := quic.DialEarly(ctx, c.pktConn, c.config.Addr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			c.conn = qc
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
		return nil, oops.In("HTTP3 Handshake").Wrap(err)
	}
	if resp.StatusCode != protocol.StatusAuthOK {
		err = oops.Errorf("authentication error, HTTP status code: %v", resp.StatusCode)
		return nil, oops.In("HTTP3 Handshake").Wrap(err)
	}
	// Auth OK
	authResp := protocol.AuthResponseFromHeader(resp.Header)
	var actualTx uint64
	if authResp.RxAuto {
		// Server asks client to use bandwidth detection,
		// ignore local bandwidth config and use BBR
		congestion.UseBBR(c.conn)
	} else {
		// actualTx = min(serverRx, clientTx)
		actualTx = authResp.Rx
		if actualTx == 0 || actualTx > c.config.BandwidthConfig.MaxTx {
			// Server doesn't have a limit, or our clientTx is smaller than serverRx
			actualTx = c.config.BandwidthConfig.MaxTx
		}
		if actualTx > 0 {
			congestion.UseBrutal(c.conn, actualTx)
		} else {
			// We don't know our own bandwidth either, use BBR
			congestion.UseBBR(c.conn)
		}
	}
	resp.Body.Close()

	if authResp.UDPEnabled {
		c.udpSM = newUDPSessionManager(c.conn)
	}

	return &HandshakeInfo{
		UDPEnabled: authResp.UDPEnabled,
		Tx:         actualTx,
	}, nil
}

func (c *Client) connected() bool {
	if c.conn == nil {
		return false
	}
	if c.conn.Context().Err() != nil {
		return false
	}
	return true
}

func (c *Client) PrepareConn(ctx context.Context) error {
	c.m.Lock()
	defer c.m.Unlock()
	if ctx.Err() != nil { // If context is already close while waiting for the lock, close the connection
		return ctx.Err()
	}
	if !c.connected() {
		c.close()
		// TODO: 什么情况下会reconnect? keepalive是不是也应该实现?
		if _, err := c.connect(ctx); err != nil {
			return err
		}
	}
	return nil
}

// openStream wraps the stream with QStream, which handles Close() properly
func (c *Client) OpenStream(ctx context.Context) (*utils.QStream, error) {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &utils.QStream{Stream: stream}, nil
}

func (c *Client) DialConn(stream *utils.QStream, addr string) (net.Conn, error) {
	// Send request
	err := protocol.WriteTCPRequest(stream, addr)
	if err != nil {
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
		return nil, err
	}
	if !ok {
		return nil, oops.In("Hysteria2").Wrapf(err, "from remote: %v", msg)
	}
	return &tcpConn{
		Orig:             stream,
		PseudoLocalAddr:  c.conn.LocalAddr(),
		PseudoRemoteAddr: c.conn.RemoteAddr(),
		Established:      true,
	}, nil
}

func (c *Client) ListenPacket() (net.PacketConn, error) {
	if c.udpSM == nil {
		return nil, oops.In("Hysteria2").New("UDP not enabled")
	}
	return c.udpSM.NewUDP()
}

func (c *Client) close() {
	if c.pktConn != nil {
		c.pktConn.Close()
	}
	if c.conn != nil {
		c.conn.CloseWithError(closeErrCodeProtocolError, "")
	}
	if c.udpSM != nil {
		c.udpSM.Close()
	}
}
