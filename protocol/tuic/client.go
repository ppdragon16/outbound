package tuic

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
)

const Ver5 = 0x5

type ClientOption struct {
	TlsConfig             *utls.Config
	QuicConfig            *quic.Config
	Uuid                  [16]byte
	Password              string
	UdpRelayMode          common.UdpRelayMode
	MaxUdpRelayPacketSize int
	CongestionController  string
	ReduceRtt             bool
	// CWND carries the brutal controller's target bandwidth (bytes per
	// second); ignored by other controllers.
	CWND uint64
}

type clientImpl struct {
	*ClientOption
	udp bool

	underConn net.PacketConn
	quicConn  quic.Connection
	connMutex sync.Mutex

	closed bool

	udpIncomingPacketsMap sync.Map

	onClose func()

	// Shared transport support: when non-nil, points to Dialer.sharedTransport.
	// All clientImpls share one UDP socket + Transport instead of creating one each.
	sharedTransportPtr **quic.Transport
	sharedProxyAddr    *net.UDPAddr
}

func (t *clientImpl) getQuicConn(ctx context.Context, dialer netproxy.Dialer, dialFn common.DialFunc) (quic.Connection, error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.quicConn != nil {
		select {
		case <-t.quicConn.Context().Done():
			t.quicConn = nil
			return nil, common.ErrClientClosed
		default:
		}
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
	var quicConn quic.Connection
	if t.ReduceRtt {
		quicConn, err = transport.DialEarly(ctx, addr, t.TlsConfig, t.QuicConfig)
	} else {
		quicConn, err = transport.Dial(ctx, addr, t.TlsConfig, t.QuicConfig)
	}
	if err != nil {
		// Only close the transport if we own it (not shared).
		if t.sharedTransportPtr == nil {
			transport.Close()
			transport.Conn.Close()
		}
		return nil, err
	}

	common.SetCongestionController(quicConn, t.CongestionController, t.CWND)

	go func() {
		_ = t.sendAuthentication(quicConn)
	}()

	if t.udp && t.UdpRelayMode == common.QUIC {
		go func() {
			_ = t.handleUniStream(quicConn)
		}()
	}
	go func() {
		_ = t.handleMessage(quicConn) // always handleMessage because tuicV5 using datagram to send the Heartbeat
	}()

	// Track underConn only for non-shared transports, so Close() skips shared ones.
	if t.sharedTransportPtr == nil {
		t.underConn = transport.Conn
	}
	t.quicConn = quicConn
	return quicConn, nil
}

func (t *clientImpl) sendAuthentication(quicConn quic.Connection) (err error) {
	defer func() {
		t.deferQuicConn(quicConn, err)
	}()
	stream, err := quicConn.OpenUniStream()
	if err != nil {
		return err
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	token, err := GenToken(quicConn.ConnectionState(), t.Uuid, t.Password)
	if err != nil {
		return err
	}
	err = NewAuthenticate(t.Uuid, token, Ver5).WriteTo(buf)
	if err != nil {
		return err
	}
	_, err = buf.WriteTo(stream)
	if err != nil {
		return err
	}
	err = stream.Close()
	if err != nil {
		return
	}
	return nil
}

func (t *clientImpl) handleUniStream(quicConn quic.Connection) (err error) {
	defer func() {
		t.deferQuicConn(quicConn, err)
	}()
	for {
		var stream quic.ReceiveStream
		stream, err = quicConn.AcceptUniStream(context.Background())
		if err != nil {
			return err
		}
		go func(stream quic.ReceiveStream) (err error) {
			var assocId uint16
			defer func() {
				t.deferQuicConn(quicConn, err)
				if err != nil && assocId != 0 {
					if val, loaded := t.udpIncomingPacketsMap.LoadAndDelete(assocId); loaded {
						val.(*Packets).Close()
					}
				}
				stream.CancelRead(0)
			}()
			reader := bufio.NewReader(stream)
			var commandHead *CommandHead
			commandHead, err = ReadCommandHead(reader)
			if err != nil {
				return err
			}
			switch commandHead.TYPE {
			case PacketType:
				var packet *Packet
				packet, err = ReadPacketWithHead(commandHead, reader)
				if err != nil {
					return
				}
				if t.udp && t.UdpRelayMode == common.QUIC {
					assocId = packet.ASSOC_ID
					if val, ok := t.udpIncomingPacketsMap.Load(assocId); ok {
						packets := val.(*Packets)
						packets.PushBack(packet)
					}
				}
			}
			return nil
		}(stream)
	}
}

func (t *clientImpl) handleMessage(quicConn quic.Connection) (err error) {
	defer func() {
		t.deferQuicConn(quicConn, err)
	}()
	receiveCtx := context.Background()
	for {
		message, err := quicConn.ReceiveDatagram(receiveCtx)
		if err != nil {
			return err
		}
		if len(message) < 2 {
			quicConn.ReleaseDatagram(message)
			continue
		}
		switch CommandType(message[1]) {
		case PacketType:
			packet, parseErr := readPacketFromMessage(message)
			// message buffer copied during parsing; release immediately.
			quicConn.ReleaseDatagram(message)
			if parseErr != nil {
				return parseErr
			}
			if t.udp && t.UdpRelayMode == common.NATIVE {
				assocId := packet.ASSOC_ID
				if val, ok := t.udpIncomingPacketsMap.Load(assocId); ok {
					val.(*Packets).PushBack(packet)
					continue
				}
			}
			// Packet not dispatched: release pool-backed resources.
			packet.Release()
		case HeartbeatType:
			quicConn.ReleaseDatagram(message)
		}
	}
}

func (t *clientImpl) deferQuicConn(quicConn quic.Connection, err error) {
	if err != nil && !errors.Is(err, common.ErrTooManyOpenStreams) {
		t.forceClose(quicConn, err)
	}
}

func (t *clientImpl) forceClose(quicConn quic.Connection, err error) {
	t.connMutex.Lock()
	if t.closed {
		t.connMutex.Unlock()
		return
	}
	t.closed = true
	if t.onClose != nil {
		go t.onClose()
		t.onClose = nil
	}
	t.connMutex.Unlock()
	// Give 10s for closing.
	time.AfterFunc(10*time.Second, func() {
		t.connMutex.Lock()
		defer t.connMutex.Unlock()
		if quicConn == nil {
			quicConn = t.quicConn
		}
		if quicConn != nil {
			if quicConn == t.quicConn {
				t.quicConn = nil
			}
		}
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		if quicConn != nil {
			_ = quicConn.CloseWithError(ProtocolError, errStr)
		}
		if t.underConn != nil {
			err = t.underConn.Close()
			t.underConn = nil
		}
		t.udpIncomingPacketsMap.Range(func(key, value any) bool {
			_ = value.(*Packets).Close()
			t.udpIncomingPacketsMap.Delete(key)
			return true
		})
	})
}

func (t *clientImpl) Close() error {
	t.forceClose(nil, common.ErrClientClosed)
	return nil
}

func (t *clientImpl) DialContextWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (net.Conn, error) {
	if t.closed {
		return nil, common.ErrClientClosed
	}
	quicConn, err := t.getQuicConn(ctx, dialer, dialFn)
	if err != nil {
		return nil, err
	}
	stream, err := func() (stream net.Conn, err error) {
		defer func() {
			t.deferQuicConn(quicConn, err)
		}()
		buf := writeConnectBuf(metadata)
		defer pool.PutBuffer(buf)
		quicStream, err := quicConn.OpenStream()
		if err != nil {
			return nil, err
		}
		stream = common.NewSafeStreamConn(
			quicStream,
			quicConn.LocalAddr(),
			quicConn.RemoteAddr(),
			nil,
		)
		if _, err = stream.Write(buf); err != nil {
			_ = stream.Close()
			return nil, err
		}
		return stream, err
	}()
	if err != nil {
		return nil, err
	}

	return stream, nil
}

// writeConnectBuf writes the tuic connect command directly into a pooled buffer,
// avoiding intermediate NewAddress/NewConnect heap allocations.
// Wire format: [VER(1)] [TYPE(1)] [addr_type(1)] [addr(variable)] [port(2)]
func writeConnectBuf(metadata *protocol.Metadata) []byte {
	var addrLen int
	var addrType byte
	var addrBytes []byte

	switch metadata.Type {
	case protocol.MetadataTypeIPv4:
		addrType = AtypIPv4
		addrLen = net.IPv4len
		if metadata.CachedAddr.IsValid() {
			ip4 := metadata.CachedAddr.As4()
			addrBytes = ip4[:]
		} else {
			addrBytes = net.ParseIP(metadata.Hostname).To4()
		}
	case protocol.MetadataTypeIPv6:
		addrType = AtypIPv6
		addrLen = net.IPv6len
		if metadata.CachedAddr.IsValid() {
			ip6 := metadata.CachedAddr.As16()
			addrBytes = ip6[:]
		} else {
			addrBytes = net.ParseIP(metadata.Hostname).To16()
		}
	case protocol.MetadataTypeDomain:
		addrType = AtypDomainName
		addrLen = 1 + len(metadata.Hostname)
		// addrBytes will be assembled directly into buf below
	default:
		addrType = AtypIPv4
		addrLen = net.IPv4len
		if metadata.CachedAddr.IsValid() {
			ip4 := metadata.CachedAddr.As4()
			addrBytes = ip4[:]
		} else {
			addrBytes = net.ParseIP(metadata.Hostname).To4()
		}
	}

	// Total: 2 (VER+TYPE) + 1 (addrType) + addrLen + 2 (port)
	totalLen := 2 + 1 + addrLen + 2
	buf := pool.GetBuffer(totalLen)
	buf[0] = Ver5
	buf[1] = byte(ConnectType)
	buf[2] = addrType
	switch metadata.Type {
	case protocol.MetadataTypeDomain:
		buf[3] = byte(len(metadata.Hostname))
		copy(buf[4:], metadata.Hostname)
	case protocol.MetadataTypeIPv4, protocol.MetadataTypeIPv6:
		copy(buf[3:], addrBytes)
	}
	binary.BigEndian.PutUint16(buf[3+addrLen:], metadata.Port)
	return buf
}

func (t *clientImpl) ListenPacketWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (*quicStreamPacketConn, error) {
	if t.closed {
		return nil, common.ErrClientClosed
	}
	quicConn, err := t.getQuicConn(ctx, dialer, dialFn)
	if err != nil {
		return nil, err
	}

	var connId uint16
	cap := 64
	if metadata.Port == 53 {
		cap = 1 // DNS: strictly 1-in-1-out
	}
	incomingPackets := NewPackets(cap)
	for {
		connId = uint16(fastrand.Intn(0xFFFF))
		_, loaded := t.udpIncomingPacketsMap.LoadOrStore(connId, incomingPackets)
		if !loaded {
			break
		}
	}
	pc := &quicStreamPacketConn{
		connId:                connId,
		quicConn:              quicConn,
		incomingPackets:       incomingPackets,
		udpRelayMode:          t.UdpRelayMode,
		maxUdpRelayPacketSize: t.MaxUdpRelayPacketSize,
		deferQuicConnFn:       t.deferQuicConn,
		closeDeferFn:          nil,
		// deFraggers is lazily initialized on first fragmented packet.
	}
	return pc, nil
}

func (t *clientImpl) setOnClose(f func()) {
	t.onClose = f
}
