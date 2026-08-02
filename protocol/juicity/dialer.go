package juicity

import (
	"context"
	"fmt"
	"math"
	"net"
	"strconv"
	"sync"
	"time"

	C "github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion/bbr"
	"github.com/daeuniverse/quic-go"
	"github.com/google/uuid"
)

func init() {
	protocol.Register("juicity", NewDialer)
}

type Dialer struct {
	clientRing *clientRing

	proxyAddress    string
	proxyAddr       *net.UDPAddr    // cached resolved proxy address
	dialFn          common.DialFunc // cached dial function, avoids per-call closure allocation
	sharedTransport *quic.Transport // shared QUIC transport across all clientImpls; created on first use
	transportMu     sync.Mutex      // protects sharedTransport
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
	// Pre-resolve proxy address to avoid per-call DNS lookups.
	proxyAddr, err := C.ResolveUDPAddr(header.ProxyAddress)
	if err != nil {
		return nil, fmt.Errorf("resolve proxy address: %w", err)
	}
	d := &Dialer{
		proxyAddress: header.ProxyAddress,
		proxyAddr:    proxyAddr,
		nextDialer:   nextDialer,
	}
	// Pre-create the dial function to avoid per-call closure allocation.
	// The first call creates a UDP socket + Transport; subsequent calls return the
	// cached transport, so all clientImpls share one UDP socket and Transport.
	d.dialFn = func(ctx context.Context, dialer netproxy.Dialer) (transport *quic.Transport, addr net.Addr, err error) {
		d.transportMu.Lock()
		defer d.transportMu.Unlock()
		if d.sharedTransport == nil {
			pc, err := dialer.ListenPacket(ctx, d.proxyAddress)
			if err != nil {
				return nil, nil, err
			}
			d.sharedTransport = &quic.Transport{Conn: pc}
		}
		return d.sharedTransport, d.proxyAddr, nil
	}
	d.clientRing = newClientRing(func(capabilityCallback func(n int64)) *clientImpl {
		ctx, cancel := context.WithCancel(context.Background())
		return &clientImpl{
			ClientOption: &ClientOption{
				TlsConfig: header.TlsConfig,
				QuicConfig: &quic.Config{
					InitialStreamReceiveWindow:     common.InitialStreamReceiveWindow,
					MaxStreamReceiveWindow:         common.MaxStreamReceiveWindow,
					InitialConnectionReceiveWindow: common.InitialConnectionReceiveWindow,
					MaxConnectionReceiveWindow:     common.MaxConnectionReceiveWindow,
					MaxIncomingStreams:             quicMaxOpenIncomingStreams,
					KeepAlivePeriod:                5 * time.Second,
					DisablePathMTUDiscovery:        false,
					EnableDatagrams:                false,
					HandshakeIdleTimeout:           8 * time.Second,
					CapabilityCallback:             capabilityCallback,
					// Use BBR from the start to avoid allocating a CUBIC sender
					// that would be immediately replaced via SetCongestionControl.
					InitialCongestionControl: bbr.NewBbrSender(
						bbr.DefaultClock{},
						bbr.GetInitialPacketSize(d.proxyAddr),
					),
				},
				Uuid:                 id,
				Password:             header.Password,
				CongestionController: header.Feature1.(string),
				CWND:                 10,
				Ctx:                  ctx,
				Cancel:               cancel,
				UnderlayAuth:         make(chan *UnderlayAuth, 64),
			},
			sharedTransportPtr: &d.sharedTransport,
			sharedProxyAddr:    d.proxyAddr,
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
		if network == "udp" {
			switch mdata.Port {
			case 0:
				iv, psk, err := d.clientRing.DialAuth(ctx, &Metadata{
					Metadata: mdata,
					Network:  network,
				}, d.nextDialer, d.dialFn)
				if err != nil {
					return nil, err
				}
				innerAddr, err := C.ResolveUDPAddr(net.JoinHostPort(mdata.Hostname, strconv.Itoa(int(mdata.Port))))
				if err != nil {
					return nil, err
				}
				transport, _, err := d.dialFn(context.TODO(), d.nextDialer)
				if err != nil {
					return nil, err
				}
				pktConn := &TransportPacketConn{
					Transport: transport,
					proxyAddr: d.proxyAddr,
					tgt:       innerAddr.AddrPort(),
					masterKey: psk,
					firstIv:   iv,
				}
				return &netproxy.BindPacketConn{
					PacketConn: pktConn,
					Address:    netproxy.NewAddr("udp", addr),
				}, nil
			}
		}
		conn, err := d.clientRing.DialContext(ctx, &Metadata{
			Metadata: mdata,
			Network:  network,
		}, d.nextDialer,
			d.dialFn,
		)
		if err != nil {
			return nil, err
		}
		if network == "tcp" {
			time.AfterFunc(100*time.Millisecond, func() {
				// avoid the situation where the server sends messages first
				if _, err = conn.Write(nil); err != nil {
					return
				}
			})
			return conn, nil
		} else {
			// UDP packet conn wrapping a QUIC stream
			return &netproxy.BindPacketConn{
				PacketConn: &PacketConn{Conn: conn},
				Address:    netproxy.NewAddr("udp", addr),
			}, nil
		}

	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

// ListenPacket implements netproxy.Dialer.
func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	// For juicity, we use a QUIC stream as the UDP transport.
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return nil, err
	}
	mdata.IsClient = true
	conn, err := d.clientRing.DialContext(ctx, &Metadata{
		Metadata: mdata,
		Network:  "udp",
	}, d.nextDialer,
		d.dialFn,
	)
	if err != nil {
		return nil, err
	}
	return &PacketConn{Conn: conn}, nil
}

func (d *Dialer) DialCmdMsg(ctx context.Context, cmd protocol.MetadataCmd) (c net.Conn, err error) {
	conn, err := d.clientRing.DialContext(ctx, &Metadata{
		Metadata: protocol.Metadata{
			Type:     protocol.MetadataTypeMsg,
			Cmd:      cmd,
			IsClient: true,
		},
	}, d.nextDialer,
		d.dialFn,
	)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Connect implements netproxy.Dialer.
func (d *Dialer) Connect() error {
	return d.nextDialer.Connect()
}

// Disconnect implements netproxy.Dialer.
// It is called when the dialer is permanently removed (e.g. via update-sub
// or daemon shutdown). It cleans up all juicity-specific resources: shared
// QUIC transport, client ring, and all clientImpl QUIC connections.
func (d *Dialer) Disconnect() error {
	// Close all clientImpls in the ring (cancels contexts, closes QUIC connections).
	_ = d.clientRing.Close()
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
