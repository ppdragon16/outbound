package client

import (
	"context"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/oops"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/pmtud"
	"github.com/daeuniverse/outbound/protocol/hysteria2/udphop"
	"github.com/daeuniverse/quic-go"
)

const (
	defaultStreamReceiveWindow    = 8 * 1024 * 1024  // 8MB initial
	defaultConnReceiveWindow      = 20 * 1024 * 1024 // 20MB initial
	defaultMaxStreamReceiveWindow = 32 * 1024 * 1024 // 32MB ceiling (netem sweep peak)
	defaultMaxConnReceiveWindow   = 64 * 1024 * 1024 // 64MB ceiling (stream x2)
	defaultMaxIdleTimeout         = 30 * time.Second
	defaultKeepAlivePeriod        = 10 * time.Second
	defaultHandshakeIdleTimeout   = 10 * time.Second
)

type Config struct {
	// Addrs is the initial list of candidate server addresses (all resolved
	// IPs for the server host, sorted IPv4-first). The Client races a QUIC
	// handshake across them and keeps the first that succeeds. All entries
	// share the same concrete type: *net.UDPAddr for a single port, or
	// *udphop.UDPHopAddr for a port-hopping range. When ServerAddr is set
	// this list only seeds the refreshable candidate cache; otherwise it is
	// the frozen candidate list (legacy behavior).
	Addrs []net.Addr
	// ServerAddr is the raw "host:port" server address (the port may be a
	// hopping range like "60000-65530"). When non-empty the Client
	// re-resolves it instead of dialing the Addrs snapshot forever: the
	// candidate list refreshes when stale (TTL) or when the previous connect
	// failed, so a rotated server entry or a dead address family heals within
	// one reconnect instead of requiring a daemon restart.
	ServerAddr string
	// PortHopping reports whether ServerAddr's port is a hopping range; it
	// selects the resolver used for refreshes.
	PortHopping     bool
	NextDialer      netproxy.Dialer
	Auth            string
	TLSConfig       utls.Config
	QUICConfig      quic.Config
	BandwidthConfig BandwidthConfig
	UDPHopInterval  time.Duration
	FastOpen        bool
	ObfsPassword    string

	filled bool // whether the fields have been verified and filled
}

// verifyAndFill fills the fields that are not set by the user with default values when possible,
// and returns an error if the user has not set a required field or has set an invalid value.
func (c *Config) verifyAndFill() error {
	if c.filled {
		return nil
	}
	if c.NextDialer == nil {
		return oops.In("Hysteria2 Config Verify").With("field", "NextDialer").With("reason", "must be set").New("invalid config")
	}
	if len(c.Addrs) == 0 {
		return oops.In("Hysteria2 Config Verify").With("field", "Addrs").With("reason", "must be non-empty").New("invalid config")
	}
	if c.QUICConfig.InitialStreamReceiveWindow == 0 {
		c.QUICConfig.InitialStreamReceiveWindow = defaultStreamReceiveWindow
	} else if c.QUICConfig.InitialStreamReceiveWindow < 16384 {
		return oops.In("Hysteria2 Config Verify").With("field", "QUICConfig.InitialStreamReceiveWindow").With("reason", "must be at least 16384").New("invalid config")
	}
	if c.QUICConfig.MaxStreamReceiveWindow == 0 {
		c.QUICConfig.MaxStreamReceiveWindow = defaultMaxStreamReceiveWindow
	} else if c.QUICConfig.MaxStreamReceiveWindow < 16384 {
		return oops.In("Hysteria2 Config Verify").With("field", "QUICConfig.MaxStreamReceiveWindow").With("reason", "must be at least 16384").New("invalid config")
	}
	if c.QUICConfig.InitialConnectionReceiveWindow == 0 {
		c.QUICConfig.InitialConnectionReceiveWindow = defaultConnReceiveWindow
	} else if c.QUICConfig.InitialConnectionReceiveWindow < 16384 {
		return oops.In("Hysteria2 Config Verify").With("field", "QUICConfig.InitialConnectionReceiveWindow").With("reason", "must be at least 16384").New("invalid config")
	}
	if c.QUICConfig.MaxConnectionReceiveWindow == 0 {
		c.QUICConfig.MaxConnectionReceiveWindow = defaultMaxConnReceiveWindow
	} else if c.QUICConfig.MaxConnectionReceiveWindow < 16384 {
		return oops.In("Hysteria2 Config Verify").With("field", "QUICConfig.MaxConnectionReceiveWindow").With("reason", "must be at least 16384").New("invalid config")
	}
	if c.QUICConfig.MaxIdleTimeout == 0 {
		c.QUICConfig.MaxIdleTimeout = defaultMaxIdleTimeout
	} else if c.QUICConfig.MaxIdleTimeout < 4*time.Second || c.QUICConfig.MaxIdleTimeout > 120*time.Second {
		return oops.In("Hysteria2 Config Verify").With("field", "QUICConfig.MaxIdleTimeout").With("reason", "must be between 4s and 120s").New("invalid config")
	}
	if c.QUICConfig.KeepAlivePeriod == 0 {
		c.QUICConfig.KeepAlivePeriod = defaultKeepAlivePeriod
	} else if c.QUICConfig.KeepAlivePeriod < 2*time.Second || c.QUICConfig.KeepAlivePeriod > 60*time.Second {
		return oops.In("Hysteria2 Config Verify").With("field", "QUICConfig.KeepAlivePeriod").With("reason", "must be between 2s and 60s").New("invalid config")
	}
	if c.QUICConfig.HandshakeIdleTimeout == 0 {
		c.QUICConfig.HandshakeIdleTimeout = defaultHandshakeIdleTimeout
	} else if c.QUICConfig.HandshakeIdleTimeout < 4*time.Second || c.QUICConfig.HandshakeIdleTimeout > 30*time.Second {
		return oops.In("Hysteria2 Config Verify").With("field", "QUICConfig.HandshakeIdleTimeout").With("reason", "must be between 4s and 30s").New("invalid config")
	}
	c.QUICConfig.DisablePathMTUDiscovery = c.QUICConfig.DisablePathMTUDiscovery || pmtud.DisablePathMTUDiscovery
	c.QUICConfig.EnableDatagrams = true

	c.filled = true
	return nil
}

// addrResolver returns the function that re-resolves ServerAddr, preserving
// the single-port / port-hopping split of the initial Addrs snapshot.
func (c *Config) addrResolver() func() ([]net.Addr, error) {
	if c.PortHopping {
		return func() ([]net.Addr, error) { return udphop.ResolveUDPHopAddrs(c.ServerAddr) }
	}
	return func() ([]net.Addr, error) { return common.ResolveUDPAddrs(c.ServerAddr) }
}

type ConnFactory interface {
	New(context.Context) (net.PacketConn, error)
}

type UdpConnFactory struct {
	NewFunc func(ctx context.Context) (net.PacketConn, error)
}

func (f *UdpConnFactory) New(ctx context.Context) (net.PacketConn, error) {
	return f.NewFunc(ctx)
}

// BandwidthConfig describes the maximum bandwidth that the server can use, in bytes per second.
type BandwidthConfig struct {
	MaxTx uint64
	MaxRx uint64
}
