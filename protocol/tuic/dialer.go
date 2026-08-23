package tuic

import (
	"context"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	C "github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
	"github.com/google/uuid"
)

func init() {
	protocol.Register("tuic", NewDialer)
}

type Dialer struct {
	clientRing *clientRing

	proxyAddress string
	proxyAddrs   []net.Addr // cached resolved proxy addresses (IPv4-first)
	dialFn       common.DialFunc
	// sharedTransport is the single QUIC transport shared across all clientImpls.
	// Created lazily on first use; all subsequent calls reuse it.
	sharedTransport *quic.Transport
	transportMu     sync.Mutex // protects sharedTransport
	nextDialer      netproxy.Dialer
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	id, err := uuid.Parse(header.User)
	if err != nil {
		return nil, fmt.Errorf("parse UUID: %w", err)
	}
	// ensure server's incoming stream can handle correctly, increase to 1.1x
	maxOpenIncomingStreams := int64(100)
	quicMaxOpenIncomingStreams := int64(maxOpenIncomingStreams)
	quicMaxOpenIncomingStreams = quicMaxOpenIncomingStreams + int64(math.Ceil(float64(quicMaxOpenIncomingStreams)/10.0))
	reservedStreamsCapability := maxOpenIncomingStreams / 5
	if reservedStreamsCapability < 1 {
		reservedStreamsCapability = 1
	}
	if reservedStreamsCapability > 5 {
		reservedStreamsCapability = 5
	}
	maxDatagramFrameSize := 1452 // quic-go MaxPacketBufferSize
	udpRelayMode := common.NATIVE
	if header.Flags&protocol.Flags_Tuic_UdpRelayModeQuic > 0 {
		// FIXME: QUIC has severe performance problems.
		// udpRelayMode = common.QUIC
	}
	// cwnd doubles as the brutal congestion controller's target bandwidth
	// (bytes per second) when congestion_control=brutal; 0 lets the
	// controller fall back to BBR.
	cwnd := 0
	if v, ok := header.Feature2.(int); ok {
		cwnd = v
	}
	// Pre-resolve proxy addresses (IPv4-first) to avoid per-call DNS lookups
	// and to race the QUIC handshake across them.
	proxyAddrs, err := C.ResolveUDPAddrs(header.ProxyAddress)
	if err != nil {
		return nil, fmt.Errorf("resolve proxy address: %w", err)
	}
	d := &Dialer{
		proxyAddress: header.ProxyAddress,
		proxyAddrs:   proxyAddrs,
		nextDialer:   nextDialer,
	}
	// Pre-create the dial function to avoid per-call closure allocation.
	// The first call creates a UDP socket + Transport; subsequent calls return the
	// cached transport, so all clientImpls share one UDP socket and Transport.
	d.dialFn = func(ctx context.Context, dialer netproxy.Dialer) (transport *quic.Transport, addrs []net.Addr, err error) {
		d.transportMu.Lock()
		defer d.transportMu.Unlock()
		if d.sharedTransport == nil {
			pc, err := dialer.ListenPacket(ctx, d.proxyAddress)
			if err != nil {
				return nil, nil, err
			}
			d.sharedTransport = &quic.Transport{Conn: pc}
		}
		return d.sharedTransport, d.proxyAddrs, nil
	}
	d.clientRing = newClientRing(func(capabilityCallback func(n int64)) *clientImpl {
		return &clientImpl{
			ClientOption: &ClientOption{
				TlsConfig: header.TlsConfig,
				QuicConfig: &quic.Config{
					InitialStreamReceiveWindow:     common.InitialStreamReceiveWindow,
					MaxStreamReceiveWindow:         common.MaxStreamReceiveWindow,
					InitialConnectionReceiveWindow: common.InitialConnectionReceiveWindow,
					MaxConnectionReceiveWindow:     common.MaxConnectionReceiveWindow,
					MaxIncomingStreams:             quicMaxOpenIncomingStreams,
					KeepAlivePeriod:                3 * time.Second,
					DisablePathMTUDiscovery:        false,
					EnableDatagrams:                true,
					HandshakeIdleTimeout:           8 * time.Second,
					CapabilityCallback:             capabilityCallback,
				},
				Uuid:                  id,
				Password:              header.Password,
				UdpRelayMode:          udpRelayMode,
				CongestionController:  header.Feature1.(string),
				ReduceRtt:             true,
				CWND:                  uint64(cwnd),
				MaxUdpRelayPacketSize: maxDatagramFrameSize,
			},
			udp:                true,
			sharedTransportPtr: &d.sharedTransport,
			sharedProxyAddrs:   d.proxyAddrs,
		}
	}, reservedStreamsCapability)
	return d, nil
}

// DialContext implements netproxy.Dialer.
func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.IsClient = true
		if network == "tcp" {
			tcpConn, err := d.clientRing.DialContextWithDialer(ctx, &mdata, d.nextDialer,
				d.dialFn,
			)
			if err != nil {
				return nil, err
			}
			return tcpConn, nil
		} else {
			udpConn, err := d.clientRing.ListenPacketWithDialer(ctx, &mdata, d.nextDialer,
				d.dialFn,
			)
			if err != nil {
				return nil, err
			}
			return &netproxy.BindPacketConn{
				PacketConn: udpConn,
				Address:    netproxy.NewAddr("udp", addr),
			}, nil
		}

	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

// ListenPacket implements netproxy.Dialer.
func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return nil, err
	}
	mdata.IsClient = true
	return d.clientRing.ListenPacketWithDialer(ctx, &mdata, d.nextDialer,
		d.dialFn,
	)
}

// Connect implements netproxy.Dialer.
func (d *Dialer) Connect() error {
	return d.nextDialer.Connect()
}

// Disconnect implements netproxy.Dialer.
// It is called when the dialer is permanently removed (e.g. via update-sub
// or daemon shutdown). It cleans up all tuic-specific resources: shared
// QUIC transport, client ring, and all clientImpl QUIC connections.
func (d *Dialer) Disconnect() error {
	// Close all clientImpls in the ring (cancels contexts, closes QUIC connections).
	d.clientRing.Close()
	// Close the shared QUIC transport and its underlying UDP socket.
	d.transportMu.Lock()
	if d.sharedTransport != nil {
		d.sharedTransport.Close()
		d.sharedTransport = nil
	}
	d.transportMu.Unlock()
	return d.nextDialer.Disconnect()
}

// Alive implements netproxy.Dialer.
func (d *Dialer) Alive() bool {
	return d.nextDialer.Alive()
}
