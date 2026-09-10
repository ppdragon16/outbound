package shadowtls

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"

	tlsx "github.com/daeuniverse/outbound/transport/tls"
)

// Config assembles a ShadowTLS v3 client.
type Config struct {
	Password string
	Version  int
	Sni      string
	// Fingerprint is a utls ClientHello fingerprint name (e.g. "chrome").
	// An empty name defaults to "chrome".
	Fingerprint   string
	AllowInsecure bool
}

// NewConn performs the ShadowTLS v3 handshake on conn and returns the
// authenticated stream.
//
// Unlike mihomo, which hooks a session-id generator into its tls fork, the
// upstream utls ClientHello is mutated in place: build the handshake state,
// inject the HMAC into the 32-byte session ID, and re-marshal.
func NewConn(ctx context.Context, conn net.Conn, cfg Config) (net.Conn, error) {
	if cfg.Version != 3 {
		return nil, fmt.Errorf("shadow-tls: only protocol version 3 is supported, got %d", cfg.Version)
	}
	if cfg.Password == "" {
		return nil, errors.New("shadow-tls: password is required")
	}

	fingerprint := cfg.Fingerprint
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	clientHelloID, err := tlsx.NameToUtlsClientHelloID(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("shadow-tls: %w", err)
	}

	tlsConfig := &utls.Config{
		ServerName:         cfg.Sni,
		InsecureSkipVerify: cfg.AllowInsecure,
		MinVersion:         utls.VersionTLS12,
		// A ClientSessionCache would resume sessions and skip the fresh
		// random session id v3 requires, so leave it nil.
	}

	stream := newStreamWrapper(conn, cfg.Password)
	uconn := utls.UClient(stream, tlsConfig, *clientHelloID)
	// BuildHandshakeState (not the ...WithoutSession variant): only the full
	// build sets clientHelloBuildStatus = BuildByUtls. Without it, the
	// handshake transparently rebuilds the ClientHello and the injected
	// session id would be lost.
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("shadow-tls: build ClientHello: %w", err)
	}
	hello := uconn.HandshakeState.Hello
	if len(hello.SessionId) != tlsSessionIDSize {
		hello.SessionId = make([]byte, tlsSessionIDSize)
	}
	// Keep hello.Raw consistent with the (possibly resized) session id so
	// the generator HMACs the layout that will actually be sent.
	if err := uconn.MarshalClientHelloNoECH(); err != nil {
		return nil, fmt.Errorf("shadow-tls: marshal ClientHello: %w", err)
	}
	if err := generateSessionID(cfg.Password)(hello.Raw, hello.SessionId); err != nil {
		return nil, fmt.Errorf("shadow-tls: %w", err)
	}
	if err := uconn.MarshalClientHelloNoECH(); err != nil {
		return nil, fmt.Errorf("shadow-tls: marshal ClientHello: %w", err)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("shadow-tls: %w", err)
	}

	_, authorized, serverRandom, handshakeHMAC := stream.Authorized()
	if serverRandom == nil {
		return nil, errors.New("shadow-tls: traffic hijacked, no ServerHello")
	}
	_ = authorized
	hmacAdd := hmac.New(sha1.New, []byte(cfg.Password))
	hmacReset(hmacAdd, serverRandom, 'C')
	hmacVerify := hmac.New(sha1.New, []byte(cfg.Password))
	hmacReset(hmacVerify, serverRandom, 'S')
	return newVerifiedConn(conn, hmacAdd, hmacVerify, handshakeHMAC), nil
}
