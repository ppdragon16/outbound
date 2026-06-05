package client

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

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

	mu            sync.Mutex
	pktConn       net.PacketConn
	conn          quic.Connection
	udpSM         *udpSessionManager
	connectCancel context.CancelFunc // set during Connect, so Disconnect can abort the handshake
}

func NewClient(config *Config) (*Client, error) {
	if err := config.verifyAndFill(); err != nil {
		return nil, err
	}
	return &Client{
		config: config,
	}, nil
}

// openStream wraps the stream with QStream, which handles Close() properly
func (c *Client) OpenStream(ctx context.Context) (*utils.QStream, error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return nil, net.ErrClosed
	}
	stream, err := conn.OpenStreamSync(ctx)
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
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if c.config.FastOpen {
		// Don't wait for the response when fast open is enabled.
		// Return the connection immediately, defer the response handling
		// to the first Read() call.
		return &tcpConn{
			Orig:             stream,
			PseudoLocalAddr:  conn.LocalAddr(),
			PseudoRemoteAddr: conn.RemoteAddr(),
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
		PseudoLocalAddr:  conn.LocalAddr(),
		PseudoRemoteAddr: conn.RemoteAddr(),
		Established:      true,
	}, nil
}

func (c *Client) ListenPacket(_ context.Context, _ string) (net.PacketConn, error) {
	c.mu.Lock()
	udpSM := c.udpSM
	c.mu.Unlock()
	if udpSM == nil {
		return nil, oops.In("Hysteria2").New("UDP not enabled")
	}
	return udpSM.NewUDP()
}

func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp":
		stream, err := c.OpenStream(ctx)
		if err != nil {
			return nil, err
		}
		conn, err := c.DialConn(stream, address)
		if err != nil {
			stream.Close()
			return nil, err
		}
		return conn, nil
	case "udp":
		conn, err := c.ListenPacket(ctx, address)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{
			PacketConn: conn,
			Address:    netproxy.NewAddr("udp", address),
		}, nil
	default:
		return nil, oops.Errorf("unsupported network: %s", network)
	}
}

func (c *Client) Alive() bool {
	if !c.config.NextDialer.Alive() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return false
	}
	if c.conn.Context().Err() != nil {
		return false
	}
	if c.udpSM != nil {
		if c.udpSM.IsClosed() {
			return false
		}
	}
	return true
}

// Handshake tuning for port-hopping retries. The outer context is the
// full dial budget (8s by default). When port hopping is enabled and
// the random port udphop picks first happens to have no hy2 server
// listening, the QUIC handshake times out silently. We rebuild udphop
// (it re-rolls the port) and try again, up to handshakeMaxAttempts
// times, each attempt bounded by handshakeAttemptTimeout.
//
// Total: 3 × 2.5s = 7.5s, fits inside the 8s outer budget.
const (
	handshakeMaxAttempts    = 3
	handshakeAttemptTimeout = 2500 * time.Millisecond
)

func (c *Client) Connect() (err error) {
	// Tear down any existing connection while holding the lock.
	c.mu.Lock()
	c.close()

	// Create a context that combines the dial timeout (8s) with
	// cancellation by Disconnect. The timeout still bounds the
	// handshake when Disconnect is not called.
	ctx, cancel := context.WithTimeout(context.Background(), netproxy.DialTimeout)
	c.connectCancel = cancel
	c.mu.Unlock()

	defer func() {
		cancel()

		// Re-acquire the lock to commit or tear down state.
		c.mu.Lock()
		if err != nil {
			c.close()
		}
		c.connectCancel = nil
		c.mu.Unlock()
	}()

	var pktConn net.PacketConn
	var conn quic.EarlyConnection
	if c.config.Addr.Network() != "udphop" {
		pktConn, conn, err = c.connectSinglePort(ctx)
	} else {
		pktConn, conn, err = c.connectPortHopping(ctx)
	}
	if err != nil {
		return err
	}

	// Commit the new connection state under the lock.
	c.mu.Lock()
	c.pktConn = pktConn
	c.conn = conn
	c.mu.Unlock()

	return nil
}

// connectSinglePort performs one handshake on a non-port-hopping address.
// No retry: if the single port doesn't work, the user must fix the URL.
// On success returns the live pktConn and quic connection; the caller
// commits them under the Client lock.
func (c *Client) connectSinglePort(ctx context.Context) (pktConn net.PacketConn, conn quic.EarlyConnection, err error) {
	attemptCtx, attemptCancel := context.WithTimeout(ctx, handshakeAttemptTimeout)
	defer attemptCancel()

	pktConn, err = c.config.NextDialer.ListenPacket(attemptCtx, c.config.Addr.String())
	if err != nil {
		return nil, nil, err
	}
	// Capture pktConn in a local so the deferred cleanup is immune to
	// named-return-value reassignment (e.g. "return nil, nil, herr"
	// sets pktConn=nil before the defer runs).
	cleanupPktConn := pktConn
	defer func() {
		if err != nil {
			cleanupPktConn.Close()
		}
	}()

	conn, resp, herr := c.tryHandshake(attemptCtx, pktConn, c.config.Addr)
	if herr != nil {
		return nil, nil, herr
	}

	return pktConn, conn, c.applyPostHandshake(resp, conn)
}

// connectPortHopping retries the QUIC handshake up to handshakeMaxAttempts
// times, each on a freshly-constructed udphop (which re-rolls a random
// port from the range). The first attempt that completes wins; on failure
// we close the previous pktConn (releasing its UDP socket and terminating
// its QUIC connection) before the next attempt.
// On success returns the live pktConn and quic connection; the caller
// commits them under the Client lock.
func (c *Client) connectPortHopping(ctx context.Context) (pktConn net.PacketConn, conn quic.EarlyConnection, err error) {
	udpHopAddr, ok := c.config.Addr.(*udphop.UDPHopAddr)
	if !ok {
		return nil, nil, oops.In("HTTP3 Handshake").
			New("hysteria2: port-hopping address has unexpected type")
	}

	// The dialFunc captured by udphop outlives a single attempt: the
	// hop goroutine invokes it on every periodic hop, so it uses the
	// outer ctx rather than any per-attempt budget. The QUIC handshake
	// itself is bounded by attemptCtx below.
	dialFunc := func(addr net.Addr) (net.Conn, error) {
		return c.config.NextDialer.DialContext(ctx, "udp", addr.String())
	}

	var lastErr error
	for range handshakeMaxAttempts {
		if ctxErr := ctx.Err(); ctxErr != nil {
			if lastErr == nil {
				lastErr = ctxErr
			}
			break
		}

		// Drop any previous attempt's resources before constructing a fresh one.
		if pktConn != nil {
			pktConn.Close()
			pktConn = nil
		}

		attemptCtx, attemptCancel := context.WithTimeout(ctx, handshakeAttemptTimeout)

		pktConn, err = udphop.NewUDPHopPacketConn(
			udpHopAddr,
			c.config.UDPHopInterval,
			dialFunc,
		)
		if err != nil {
			attemptCancel()
			lastErr = err
			continue
		}

		conn, resp, herr := c.tryHandshake(attemptCtx, pktConn, c.config.Addr)
		attemptCancel()
		if herr != nil {
			lastErr = herr
			pktConn.Close()
			pktConn = nil
			continue
		}

		// Handshake succeeded — commit and apply post-handshake config.
		return pktConn, conn, c.applyPostHandshake(resp, conn)
	}

	if lastErr != nil {
		return nil, nil, oops.In("HTTP3 Handshake").
			With("attempts", handshakeMaxAttempts).
			With("portHopping", true).
			Wrap(lastErr)
	}
	return nil, nil, oops.In("HTTP3 Handshake").
		With("attempts", handshakeMaxAttempts).
		With("portHopping", true).
		New("hysteria2: no port in range responded within dial budget")
}

// tryHandshake performs one QUIC dial + auth HTTP roundtrip on the given
// pktConn (with the given remote address). On success it returns the live
// quic connection and the auth response. On failure the caller is
// expected to close pktConn, which terminates the QUIC connection.
//
// pktConn and remoteAddr are passed explicitly (rather than read from
// c.pktConn / c.config.Addr) so multiple attempts can run in parallel
// without trampling each other's state.
func (c *Client) tryHandshake(ctx context.Context, pktConn net.PacketConn, remoteAddr net.Addr) (quic.EarlyConnection, *http.Response, error) {
	var conn quic.EarlyConnection
	rt := &http3.Transport{
		TLSClientConfig: &c.config.TLSConfig,
		QUICConfig:      &c.config.QUICConfig,
		Dial: func(dialCtx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			qc, err := quic.DialEarly(dialCtx, pktConn, remoteAddr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			conn = qc
			return qc, nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, protocol.AuthURL, nil)
	if err != nil {
		return nil, nil, oops.
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
		return nil, nil, oops.In("HTTP3 Handshake").Wrap(err)
	}
	if resp.StatusCode != protocol.StatusAuthOK {
		resp.Body.Close()
		return nil, nil, oops.Errorf("authentication error, HTTP status code: %v", resp.StatusCode)
	}
	return conn, resp, nil
}

// applyPostHandshake configures congestion control and the optional UDP
// session manager based on the auth response. Called after a successful
// handshake before c.conn has been committed.
func (c *Client) applyPostHandshake(resp *http.Response, conn quic.Connection) error {
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
	resp.Body.Close()

	if authResp.UDPEnabled {
		c.udpSM = newUDPSessionManager(conn)
	}

	return nil
}

func (c *Client) Disconnect() error {
	// If Connect() is in progress, cancel its context first so the
	// handshake I/O returns promptly. Otherwise we would block on the
	// mutex for up to DialTimeout (8s) waiting for Connect to give up.
	c.mu.Lock()
	if c.connectCancel != nil {
		c.connectCancel()
	}
	c.mu.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.close()
	return nil
}

func (c *Client) close() {
	if c.pktConn != nil {
		c.pktConn.Close()
		c.pktConn = nil
	}
	if c.conn != nil {
		c.conn.CloseWithError(closeErrCodeProtocolError, "")
		c.conn = nil
	}
	if c.udpSM != nil {
		c.udpSM.Close()
		c.udpSM = nil
	}
}
