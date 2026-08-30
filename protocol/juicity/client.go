package juicity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/daeuniverse/outbound/ciphers"
	C "github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/tuic"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
)

var (
	CipherConf = ciphers.AeadCiphersConf["chacha20-poly1305"]
)

const (
	UnderlaySaltLen = 32
)

func init() {
	if CipherConf.SaltLen != UnderlaySaltLen {
		panic("CipherConf.SaltLen != UnderlaySaltLen")
	}
}

type UnderlayAuth struct {
	IV       []byte
	Psk      []byte
	Metadata *Metadata
}

func (a *UnderlayAuth) PackFromPool() []byte {
	buf := pool.GetBuffer(a.Metadata.Len() + len(a.IV) + len(a.Psk))
	copy(buf, a.IV)
	copy(buf[len(a.IV):], a.Psk)
	a.Metadata.PackTo(buf[len(a.IV)+len(a.Psk):])
	return buf
}

func (a *UnderlayAuth) Unpack(r io.Reader) (n int, err error) {
	var _n int
	a.IV = make([]byte, CipherConf.SaltLen)
	if _n, err = io.ReadFull(r, a.IV); err != nil {
		return 0, err
	}
	n += _n
	a.Psk = make([]byte, CipherConf.KeyLen)
	if _n, err = io.ReadFull(r, a.Psk); err != nil {
		return 0, err
	}
	n += _n
	a.Metadata = &Metadata{}
	if _n, err = a.Metadata.Unpack(r); err != nil {
		return 0, err
	}
	n += _n
	return n, nil
}

type ClientOption struct {
	TlsConfig            *utls.Config
	QuicConfig           *quic.Config
	Uuid                 [16]byte
	Password             string
	CongestionController string
	CWND                 uint64
	Ctx                  context.Context
	Cancel               func()
	UnderlayAuth         chan *UnderlayAuth
}

type clientImpl struct {
	*ClientOption

	quicConn  quic.Connection
	underConn net.PacketConn
	connMutex sync.Mutex

	detachCallback func()

	// Shared transport support: when non-nil, points to Dialer.sharedTransport.
	// clientImpls share one UDP socket + Transport instead of creating one each.
	sharedTransportPtr **quic.Transport
	// sharedAddrs is the Dialer's refreshable candidate cache; Get re-resolves
	// when the list is stale or the previous connect failed.
	sharedAddrs *C.AddrCache
}

func (t *clientImpl) getQuicConn(ctx context.Context, dialer netproxy.Dialer, dialFn common.DialFunc) (quic.Connection, error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.quicConn != nil {
		// Detect stale cached connections: if the QUIC connection's context
		// is already done (server-side close, network loss, etc.), clean up
		// and force a new connection instead of returning a dead one.
		select {
		case <-t.quicConn.Context().Done():
			t.closeConnectionLocked(quicContextErr(t.quicConn.Context()))
			return nil, common.ErrClientClosed
		default:
		}
		return t.quicConn, nil
	}
	// Try the shared transport first (nil means this clientImpl manages its own).
	var transport *quic.Transport
	var addrs []net.Addr
	var err error
	if t.sharedTransportPtr != nil {
		if st := *t.sharedTransportPtr; st != nil {
			transport = st
			if t.sharedAddrs != nil {
				// Get never fails here: the cache is always seeded by
				// NewDialer and resolution failures fall back to the cached
				// list.
				addrs, _ = t.sharedAddrs.Get()
			}
		}
	}
	if transport == nil {
		transport, addrs, err = dialFn(ctx, dialer)
		if err != nil {
			return nil, err
		}
	}
	// Race the QUIC handshake across all resolved addresses (happy-eyeballs).
	quicConn, err := C.Race(ctx, addrs, func(ctx context.Context, addr net.Addr) (quic.Connection, error) {
		return transport.Dial(ctx, addr, t.TlsConfig, t.QuicConfig)
	}, func(qc quic.Connection) {
		_ = qc.CloseWithError(0, "")
	})
	// Feed the outcome back so a failed connect forces re-resolution next
	// time (e.g. rotated entry IPs).
	if t.sharedAddrs != nil {
		t.sharedAddrs.Report(err == nil)
	}
	if err != nil {
		// Only close the transport if we own it (not shared).
		if t.sharedTransportPtr == nil {
			transport.Close()
			_ = transport.Conn.Close()
		}
		return nil, err
	}

	// BBR congestion controller is already set via QuicConfig.InitialCongestionControl.
	// No need to call SetCongestionController again — doing so would create a second
	// BBR sender and immediately GC the first.
	if t.QuicConfig.InitialCongestionControl == nil {
		common.SetCongestionController(quicConn, t.CongestionController, t.CWND)
	}

	go func() {
		if err := t.sendAuthentication(quicConn); err != nil {
			_ = t.Close()
		}
	}()

	// Track underConn only for non-shared transports, so Close() skips shared ones.
	if t.sharedTransportPtr == nil {
		t.underConn = transport.Conn
	}
	t.quicConn = quicConn
	return quicConn, nil
}

func (t *clientImpl) sendAuthentication(quicConn quic.Connection) (err error) {
	uniStream, err := quicConn.OpenUniStream()
	if err != nil {
		return err
	}
	defer func() { _ = uniStream.Close() }()
	buf := pool.NewPooledBuffer()
	defer buf.Reset()
	token, err := tuic.GenToken(quicConn.ConnectionState(), t.Uuid, t.Password)
	if err != nil {
		return err
	}
	err = tuic.NewAuthenticate(t.Uuid, token, Version0).WriteTo(buf)
	if err != nil {
		return err
	}
	_, err = buf.WriteTo(uniStream)
	if err != nil {
		return err
	}
	for {
		var auth *UnderlayAuth
		select {
		case <-t.Ctx.Done():
			return t.Ctx.Err()
		case <-quicConn.Context().Done():
			return quicContextErr(quicConn.Context())
		case auth = <-t.UnderlayAuth:
		}
		buf := auth.PackFromPool()
		_, err = uniStream.Write(buf)
		pool.PutBuffer(buf)
		if err != nil {
			_ = t.Close()
			return err
		}
	}
}

func (t *clientImpl) Close() error {
	t.connMutex.Lock()
	select {
	case <-t.Ctx.Done():
		t.connMutex.Unlock()
		return nil
	default:
		t.Cancel()
	}
	if t.detachCallback != nil {
		go t.detachCallback()
		t.detachCallback = nil
	}
	t.connMutex.Unlock()
	// Give 10s for closing.
	time.AfterFunc(10*time.Second, func() {
		t.connMutex.Lock()
		defer t.connMutex.Unlock()
		if t.quicConn != nil {
			_ = t.quicConn.CloseWithError(tuic.ProtocolError, common.ErrClientClosed.Error())
			t.quicConn = nil
		}
		if t.underConn != nil {
			_ = t.underConn.Close()
			t.underConn = nil
		}
	})
	return nil
}

func (t *clientImpl) DialContext(ctx context.Context, metadata *Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (*Conn, error) {
	select {
	case <-t.Ctx.Done():
		return nil, common.ErrClientClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	quicConn, err := t.getQuicConn(ctx, dialer, dialFn)
	if err != nil {
		if errors.Is(err, common.ErrClientClosed) {
			return nil, err
		}
		return nil, fmt.Errorf("getQuicConn: %w", err)
	}
	quicStream, err := quicConn.OpenStream()
	if err != nil {
		if isStreamLimitReached(err) {
			return nil, common.ErrTooManyOpenStreams
		}
		if t.handleIfConnectionClosed(err, quicConn) {
			return nil, common.ErrClientClosed
		}
		return nil, fmt.Errorf("OpenStream: %w", err)
	}
	stream := NewConn(
		quicStream,
		metadata,
		nil,
		quicConn.LocalAddr(),
		quicConn.RemoteAddr(),
	)
	return stream, nil
}

func (t *clientImpl) DialAuth(ctx context.Context, metadata *Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (iv []byte, psk []byte, err error) {
	select {
	case <-t.Ctx.Done():
		return nil, nil, common.ErrClientClosed
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}
	quicConn, err := t.getQuicConn(ctx, dialer, dialFn)
	if err != nil {
		if errors.Is(err, common.ErrClientClosed) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("getQuicConn: %w", err)
	}
	iv = make([]byte, CipherConf.SaltLen)
	psk = make([]byte, CipherConf.KeyLen)
	iv[0], iv[1] = 0, 0
	_, _ = fastrand.Read(iv[2:])
	_, _ = fastrand.Read(psk)
	auth := &UnderlayAuth{
		IV:       iv,
		Psk:      psk,
		Metadata: metadata,
	}
	// Non-blocking send with connection-death detection: if the QUIC
	// connection died between getQuicConn and this send, detect it and
	// clean up so the ring retries on the next node.
	select {
	case t.UnderlayAuth <- auth:
	case <-quicConn.Context().Done():
		if t.handleIfConnectionClosed(quicContextErr(quicConn.Context()), quicConn) {
			return nil, nil, common.ErrClientClosed
		}
		return nil, nil, quicContextErr(quicConn.Context())
	case <-t.Ctx.Done():
		return nil, nil, common.ErrClientClosed
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	return iv, psk, nil
}

// handleIfConnectionClosed detaches the connection from the client pool and
// closes it when a permanent error (non-temporary) is encountered. Transient
// net.Error.Temporary() failures are skipped — the connection may recover.
// originConn is the connection that produced err; a stale failure from a
// connection that was already replaced must not tear down the replacement.
func (t *clientImpl) handleIfConnectionClosed(err error, originConn quic.Connection) bool {
	if err == nil {
		return false
	}
	// A stream-scoped error (RESET_STREAM / STOP_SENDING on one stream) is not
	// a connection failure: tearing down the shared tunnel would kill every
	// other live stream on it.
	if _, ok := errors.AsType[*quic.StreamError](err); ok {
		return false
	}
	if netErr, ok := err.(net.Error); ok && netErr.Temporary() { // nolint:staticcheck
		return false
	}
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.quicConn != originConn {
		return false
	}
	t.closeConnectionLocked(err)
	return true
}

// quicContextErr extracts a meaningful error from a QUIC connection context,
// preferring context.Cause over context.Err.
func quicContextErr(ctx context.Context) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return common.ErrClientClosed
}

// closeConnectionLocked tears down the connection: detaches from ring,
// cancels context, closes QUIC conn and underlying UDP socket.
// Must be called with connMutex held.
func (t *clientImpl) closeConnectionLocked(err error) {
	if t.detachCallback != nil {
		go t.detachCallback()
		t.detachCallback = nil
	}
	select {
	case <-t.Ctx.Done():
	default:
		t.Cancel()
	}
	if t.quicConn != nil {
		errStr := common.ErrClientClosed.Error()
		if err != nil {
			errStr = err.Error()
		}
		_ = t.quicConn.CloseWithError(tuic.ProtocolError, errStr)
		t.quicConn = nil
	}
	if t.underConn != nil {
		_ = t.underConn.Close()
		t.underConn = nil
	}
}

// isStreamLimitReached reports whether err is a recoverable stream-limit
// error. The client ring should retry on the next connection rather than
// destroying this one.
func isStreamLimitReached(err error) bool {
	if _, ok := errors.AsType[*quic.StreamLimitReachedError](err); ok {
		return true
	}
	_, ok := errors.AsType[quic.StreamLimitReachedError](err)
	return ok
}

func (t *clientImpl) setOnClose(f func()) {
	t.detachCallback = f
}
