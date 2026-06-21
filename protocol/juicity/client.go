package juicity

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
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
	TlsConfig            *tls.Config
	QuicConfig           *quic.Config
	Uuid                 [16]byte
	Password             string
	CongestionController string
	CWND                 int
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
	sharedProxyAddr    *net.UDPAddr
}

func (t *clientImpl) getQuicConn(ctx context.Context, dialer netproxy.Dialer, dialFn common.DialFunc) (quic.Connection, error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.quicConn != nil {
		return t.quicConn, nil
	}
	// Try the shared transport first (nil means this clientImpl manages its own).
	var transport *quic.Transport
	var addr net.Addr
	var err error
	if t.sharedTransportPtr != nil {
		if st := *t.sharedTransportPtr; st != nil {
			transport = st
			addr = t.sharedProxyAddr
		}
	}
	if transport == nil {
		transport, addr, err = dialFn(ctx, dialer)
		if err != nil {
			return nil, err
		}
	}
	quicConn, err := transport.Dial(ctx, addr, t.TlsConfig, t.QuicConfig)
	if err != nil {
		// Only close the transport if we own it (not shared).
		if t.sharedTransportPtr == nil {
			transport.Close()
			transport.Conn.Close()
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
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
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
	defer uniStream.Close()
	for {
		var auth *UnderlayAuth
		select {
		case <-t.Ctx.Done():
			return t.Ctx.Err()
		case auth = <-t.UnderlayAuth:
		}
		buf := auth.PackFromPool()
		_, err = uniStream.Write(buf)
		pool.PutBuffer(buf)
		if err != nil {
			t.Close()
			return err
		}
	}
}

func (t *clientImpl) Close() (err error) {
	t.connMutex.Lock()
	select {
	case <-t.Ctx.Done():
		t.connMutex.Unlock()
		return
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
			err = t.quicConn.CloseWithError(tuic.ProtocolError, common.ErrClientClosed.Error())
			t.quicConn = nil
		}
		if t.underConn != nil {
			err = t.underConn.Close()
			t.underConn = nil
		}
	})
	return err
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
		return nil, fmt.Errorf("getQuicConn: %w", err)
	}
	quicStream, err := quicConn.OpenStream()
	if err != nil {
		t.connMutex.Lock()
		// Detach it from pool due to bad connection.
		if t.detachCallback != nil {
			go t.detachCallback()
			t.detachCallback = nil
		}
		t.connMutex.Unlock()
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
	_, err = t.getQuicConn(ctx, dialer, dialFn)
	if err != nil {
		return nil, nil, fmt.Errorf("getQuicConn: %w", err)
	}
	iv = make([]byte, CipherConf.SaltLen)
	psk = make([]byte, CipherConf.KeyLen)
	iv[0], iv[1] = 0, 0
	_, _ = fastrand.Read(iv[2:])
	_, _ = fastrand.Read(psk)
	t.UnderlayAuth <- &UnderlayAuth{
		IV:       iv,
		Psk:      psk,
		Metadata: metadata,
	}
	return iv, psk, nil
}

func (t *clientImpl) setOnClose(f func()) {
	t.detachCallback = f
}
