package client

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/pmtud"
	"github.com/samber/oops"
)

const (
	defaultStreamReceiveWindow = 8388608                            // 8MB
	defaultConnReceiveWindow   = defaultStreamReceiveWindow * 5 / 2 // 20MB
	defaultMaxIdleTimeout      = 30 * time.Second
	defaultKeepAlivePeriod     = 10 * time.Second
)

type Config struct {
	ProxyAddress    string
	Addr            net.Addr
	NextDialer      netproxy.Dialer
	Auth            string
	TLSConfig       TLSConfig
	QUICConfig      QUICConfig
	BandwidthConfig BandwidthConfig
	UDPHopInterval  time.Duration
	FastOpen        bool

	filled bool // whether the fields have been verified and filled
}

// verifyAndFill fills the fields that are not set by the user with default values when possible,
// and returns an error if the user has not set a required field or has set an invalid value.
func (c *Config) verifyAndFill() error {
	if c.filled {
		return nil
	}
	if c.ProxyAddress == "" {
		return oops.In("Hysteria2 Config Verify").With("field", "ProxyAddress").With("reason", "must be set").New("invalid config")
	}
	if c.NextDialer == nil {
		return oops.In("Hysteria2 Config Verify").With("field", "NextDialer").With("reason", "must be set").New("invalid config")
	}
	if c.QUICConfig.InitialStreamReceiveWindow == 0 {
		c.QUICConfig.InitialStreamReceiveWindow = defaultStreamReceiveWindow
	} else if c.QUICConfig.InitialStreamReceiveWindow < 16384 {
		return oops.In("Hysteria2 Config Verify").With("field", "QUICConfig.InitialStreamReceiveWindow").With("reason", "must be at least 16384").New("invalid config")
	}
	if c.QUICConfig.MaxStreamReceiveWindow == 0 {
		c.QUICConfig.MaxStreamReceiveWindow = defaultStreamReceiveWindow
	} else if c.QUICConfig.MaxStreamReceiveWindow < 16384 {
		return oops.In("Hysteria2 Config Verify").With("field", "QUICConfig.MaxStreamReceiveWindow").With("reason", "must be at least 16384").New("invalid config")
	}
	if c.QUICConfig.InitialConnectionReceiveWindow == 0 {
		c.QUICConfig.InitialConnectionReceiveWindow = defaultConnReceiveWindow
	} else if c.QUICConfig.InitialConnectionReceiveWindow < 16384 {
		return oops.In("Hysteria2 Config Verify").With("field", "QUICConfig.InitialConnectionReceiveWindow").With("reason", "must be at least 16384").New("invalid config")
	}
	if c.QUICConfig.MaxConnectionReceiveWindow == 0 {
		c.QUICConfig.MaxConnectionReceiveWindow = defaultConnReceiveWindow
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
	c.QUICConfig.DisablePathMTUDiscovery = c.QUICConfig.DisablePathMTUDiscovery || pmtud.DisablePathMTUDiscovery

	c.filled = true
	return nil
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

// TLSConfig contains the TLS configuration fields that we want to expose to the user.
type TLSConfig struct {
	ServerName            string
	InsecureSkipVerify    bool
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	RootCAs               *x509.CertPool
}

// QUICConfig contains the QUIC configuration fields that we want to expose to the user.
type QUICConfig struct {
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
	MaxIdleTimeout                 time.Duration
	KeepAlivePeriod                time.Duration
	DisablePathMTUDiscovery        bool // The server may still override this to true on unsupported platforms.
}

// BandwidthConfig describes the maximum bandwidth that the server can use, in bytes per second.
type BandwidthConfig struct {
	MaxTx uint64
	MaxRx uint64
}
