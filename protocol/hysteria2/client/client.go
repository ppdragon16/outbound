package client

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/daeuniverse/outbound/pkg/oops"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/utils"
	"github.com/daeuniverse/outbound/protocol/hysteria2/obfs"
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
	addrs  *addrsCache // nil when config.ServerAddr is empty: frozen candidates

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
	c := &Client{
		config: config,
	}
	if config.ServerAddr != "" {
		c.addrs = newAddrsCache(config.Addrs, config.addrResolver())
	}
	return c, nil
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

// dialOutcome is the result of a successful dial on a single candidate address.
type dialOutcome struct {
	pktConn net.PacketConn
	conn    quic.EarlyConnection
	resp    *http.Response // non-nil on success; consumed by applyPostHandshake or teardown
}

// teardownDialOutcome closes a successful-but-unused dial outcome.
func teardownDialOutcome(r dialOutcome) {
	if r.resp != nil {
		r.resp.Body.Close()
	}
	if r.conn != nil {
		r.conn.CloseWithError(closeErrCodeProtocolError, "")
	}
	if r.pktConn != nil {
		r.pktConn.Close()
	}
}

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

	// Report the connect outcome so the candidate cache knows whether to
	// keep serving the current list or force a re-resolution next time.
	// Registered before the teardown defer, so it runs after err is final.
	defer c.reportConnect(err == nil)

	// Candidate list for this attempt: refreshed per TTL / after a failed
	// connect when the server address is re-resolvable, otherwise the
	// build-time snapshot.
	addrs, aerr := c.candidates()
	if aerr != nil {
		return aerr
	}

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

	var outcome dialOutcome
	var derr error
	if addrs[0].Network() != "udphop" {
		outcome, derr = c.connectSinglePort(ctx, addrs)
	} else {
		outcome, derr = c.connectPortHopping(ctx, addrs)
	}
	if derr != nil {
		err = derr
		return err
	}

	// Apply post-handshake config to the single winner. This runs outside the
	// race so it's only ever applied to the winner, never by concurrent losers.
	udpSM, aerr := c.applyPostHandshake(outcome.resp, outcome.conn)
	if aerr != nil {
		outcome.pktConn.Close()
		outcome.conn.CloseWithError(closeErrCodeProtocolError, "")
		err = aerr
		return err
	}

	// Commit the new connection state atomically under the lock, so a
	// concurrent Alive/Disconnect never observes a half-committed state.
	c.mu.Lock()
	c.pktConn = outcome.pktConn
	c.conn = outcome.conn
	c.udpSM = udpSM
	c.mu.Unlock()

	return nil
}

// candidates returns the address list to race this connect attempt with:
// refreshed (per TTL / after a failed connect) when the server address is
// re-resolvable, otherwise the frozen build-time snapshot.
func (c *Client) candidates() ([]net.Addr, error) {
	if c.addrs == nil {
		return c.config.Addrs, nil
	}
	return c.addrs.get()
}

// reportConnect feeds the connect outcome back into the candidate cache.
func (c *Client) reportConnect(success bool) {
	if c.addrs != nil {
		c.addrs.report(success)
	}
}

// connectSinglePort races a single handshake across all candidate addresses
// (happy-eyeballs). No retry per address: if a single port doesn't work on any
// address, the user must fix the URL. On success returns the winner's pktConn
// and quic connection; the caller commits them under the Client lock.
func (c *Client) connectSinglePort(ctx context.Context, addrs []net.Addr) (dialOutcome, error) {
	return common.Race(ctx, addrs, c.dialSinglePortAddr, teardownDialOutcome)
}

// dialSinglePortAddr performs one handshake on one non-port-hopping address.
// On error it closes its own pktConn before returning.
func (c *Client) dialSinglePortAddr(ctx context.Context, addr net.Addr) (dialOutcome, error) {
	attemptCtx, attemptCancel := context.WithTimeout(ctx, handshakeAttemptTimeout)
	defer attemptCancel()

	pktConn, err := c.config.NextDialer.ListenPacket(attemptCtx, addr.String())
	if err != nil {
		return dialOutcome{}, err
	}
	if c.config.ObfsPassword != "" {
		wrapped, werr := obfs.WrapPacketConnSalamander(pktConn, []byte(c.config.ObfsPassword))
		if werr != nil {
			pktConn.Close()
			return dialOutcome{}, werr
		}
		pktConn = wrapped
	}

	conn, resp, herr := c.tryHandshake(attemptCtx, pktConn, addr)
	if herr != nil {
		pktConn.Close()
		return dialOutcome{}, herr
	}

	return dialOutcome{pktConn: pktConn, conn: conn, resp: resp}, nil
}

// connectPortHopping races the port-hopping handshake across all candidate
// addresses (happy-eyeballs). Each address runs the retry loop independently,
// re-rolling a random port on every attempt. The first address whose handshake
// completes wins; the others are torn down.
func (c *Client) connectPortHopping(ctx context.Context, addrs []net.Addr) (dialOutcome, error) {
	return common.Race(ctx, addrs, func(ctx context.Context, addr net.Addr) (dialOutcome, error) {
		udpHopAddr, ok := addr.(*udphop.UDPHopAddr)
		if !ok {
			return dialOutcome{}, oops.In("HTTP3 Handshake").
				New("hysteria2: port-hopping address has unexpected type")
		}
		return c.dialPortHoppingAddr(ctx, udpHopAddr)
	}, teardownDialOutcome)
}

// dialPortHoppingAddr retries the QUIC handshake up to handshakeMaxAttempts
// times on a single port-hopping address, each attempt re-rolling a random
// port from the range. On error it closes its own pktConn before returning.
func (c *Client) dialPortHoppingAddr(ctx context.Context, udpHopAddr *udphop.UDPHopAddr) (dialOutcome, error) {
	// The dialFunc captured by udphop outlives the handshake budget: the hop
	// goroutine invokes it on every periodic hop for the lifetime of the
	// connection. It must NOT capture ctx (the race/dial budget), which is
	// cancelled as soon as the race concludes — that would silently stop all
	// future port hops. UDP dialing is non-blocking, so a background context
	// is safe: the hop loop itself is bounded by the udphop's own ctx.
	dialFunc := func(addr net.Addr) (net.Conn, error) {
		return c.config.NextDialer.DialContext(context.Background(), "udp", addr.String())
	}

	var pktConn net.PacketConn
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

		var err error
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
		if c.config.ObfsPassword != "" {
			opc, oerr := obfs.WrapPacketConnSalamander(pktConn, []byte(c.config.ObfsPassword))
			if oerr != nil {
				attemptCancel()
				pktConn.Close()
				pktConn = nil
				lastErr = oerr
				continue
			}
			pktConn = opc
		}

		conn, resp, herr := c.tryHandshake(attemptCtx, pktConn, udpHopAddr)
		attemptCancel()
		if herr != nil {
			lastErr = herr
			pktConn.Close()
			pktConn = nil
			continue
		}

		// Handshake succeeded — return the outcome. applyPostHandshake runs
		// once on the race winner (outside the race) to avoid concurrent
		// access to c.udpSM.
		return dialOutcome{pktConn: pktConn, conn: conn, resp: resp}, nil
	}

	if lastErr != nil {
		return dialOutcome{}, oops.In("HTTP3 Handshake").
			With("attempts", handshakeMaxAttempts).
			With("portHopping", true).
			Wrap(lastErr)
	}
	return dialOutcome{}, oops.In("HTTP3 Handshake").
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
		Dial: func(dialCtx context.Context, _ string, tlsCfg *utls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
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
// session manager based on the auth response. It returns the newly-created
// session manager (nil when UDP is disabled) so the caller can commit it
// atomically with the connection under the client lock — writing c.udpSM here
// would race with Alive/Disconnect/ListenPacket, which read it under the lock.
func (c *Client) applyPostHandshake(resp *http.Response, conn quic.Connection) (udpSM *udpSessionManager, err error) {
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
		udpSM = newUDPSessionManager(conn)
	}
	return udpSM, nil
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
