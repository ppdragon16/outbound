package meek

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type Dialer struct {
	protocol.StatelessDialer
	addr       string
	url        string
	serverName string
	skipVerify bool
	alpn       []string
	tripper    *httpTripperClient
}

func NewDialer(s string, d netproxy.Dialer) (*Dialer, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("NewMeek: %w", err)
	}

	m := &Dialer{
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: d,
		},
		addr: u.Host,
	}

	query := u.Query()
	m.url = query.Get("url")
	if m.url == "" {
		return nil, fmt.Errorf("NewMeek: url is empty")
	}

	meekUrl, err := url.Parse(m.url)
	if err != nil {
		return nil, fmt.Errorf("NewMeek: %w", err)
	}
	if meekUrl.Scheme != "https" {
		return nil, fmt.Errorf("NewMeek: unimplemented backdrop")
	}

	// skipVerify
	if query.Get("allowInsecure") == "true" || query.Get("allowInsecure") == "1" ||
		query.Get("skipVerify") == "true" || query.Get("skipVerify") == "1" {
		m.skipVerify = true
	}
	// alpn
	if query.Get("alpn") != "" {
		// Set it not nil.
		m.alpn = strings.Split(query.Get("alpn"), ",")
	} else {
		m.alpn = []string{"h2", "http/1.1"}
	}
	// serverName
	m.serverName = query.Get("serverName")
	if m.serverName == "" {
		m.serverName = u.Hostname()
	}

	// The HTTP transport is built once per dialer: the meek URL, the TLS
	// settings and the parent dialer never vary per connection, so no
	// cross-proxy cache is needed.
	tripper := &httpTripperClient{
		url: m.url,
		roundTripper: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				rc, err := d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, fmt.Errorf("[Meek]: dial to %s: %w", addr, err)
				}
				return rc, nil
			},
			TLSClientConfig: &tls.Config{
				ServerName:         m.serverName,
				InsecureSkipVerify: m.skipVerify,
				NextProtos:         m.alpn,
			},
			// Without an idle timeout the transport pins its TLS
			// connections (and their read/write goroutines) for the
			// process lifetime; nothing reaps transports explicitly.
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
	m.tripper = tripper

	return m, nil
}

func (m *Dialer) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp":
		clientConfig := &config{
			MaxWriteSize:             65536,
			WaitSubsequentWriteMs:    10,
			InitialPollingIntervalMs: 100,
			MaxPollingIntervalMs:     1000,
			MinPollingIntervalMs:     10,
			BackoffFactor:            1.5,
			FailedRetryIntervalMs:    1000,
		}

		assembler := newAssemblerClient(m.tripper, clientConfig)
		session, err := assembler.NewSession(context.Background())
		if err != nil {
			return nil, err
		}

		return session.(net.Conn), nil
	case "udp":
		return nil, fmt.Errorf("%w: meek+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (m *Dialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return nil, fmt.Errorf("%w: meek does not support UDP", netproxy.UnsupportedTunnelTypeError)
}
