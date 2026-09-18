// Modified from https://github.com/Reality/Xray-core/blob/fbc56b88da2808e3181add4935c143e319772c93/transport/internet/reality/reality.go

package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/coalesce"
	"github.com/daeuniverse/outbound/pkg/logger"
	"github.com/daeuniverse/outbound/protocol"
	utls "github.com/refraction-networking/utls"

	"github.com/daeuniverse/outbound/common/ua"

	xtls "crypto/tls"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

var (
	Reality_Version_x byte = 1
	Reality_Version_y byte = 8
	Reality_Version_z byte = 10
)

// realityHelloAttempts bounds how many ClientHellos the dialer generates before
// it gives up on a fingerprint. A fingerprint only authenticates when its hello
// carries a TLS 1.3 key share, and uTLS's randomized parrots (fp=random,
// fp=randomized) offer one in only about 40% of handshakes: measured over 3000
// builds each with the pinned uTLS revision, HelloRandomized,
// HelloRandomizedALPN and HelloRandomizedNoALPN landed at 37.7%-41.5%, while
// Chrome, Firefox, Safari and iOS landed at 100%.
//
// A rebuild happens before anything is sent, costs about 0.035ms, and reuses
// the same underlay, so it is free compared with the dial itself. Three attempts
// left the randomized fingerprints failing 0.6^3 = 22% of the time; sixteen
// bring that to 0.03%. Fingerprints that never carry a key share (for example
// Android 11's OkHttp parrot or the pre-TLS1.3 360 parrots) still fail after a
// bounded number of local rebuilds with an error that names the fingerprint.
const realityHelloAttempts = 16

// realityBothShapesBackoff is how long a REALITY server that rejected both
// ClientHello shapes (post-quantum free and hybrid) is dialled with a single
// attempt before the second shape is probed again.
const realityBothShapesBackoff = 5 * time.Minute

// realitySealAuth seals the REALITY authentication payload into the ClientHello
// session ID and copies the ciphertext back into the raw ClientHello.
//
// REALITY always authenticates with AES-GCM keyed by the 32-byte REALITY auth
// key (AES-256-GCM): Xray (crypto.NewAesGcm) and sing-box through
// metacubex-utls both open the payload with AES-GCM no matter which cipher
// suites the ClientHello offers. Deriving the AEAD from the
// offered suites is therefore wrong: an earlier revision preferred
// ChaCha20-Poly1305 whenever the first recognized suite was not AES-GCM, which
// randomized fingerprints (fp=random, fp=randomized) hit on a fraction of
// dials. The server then cannot open the payload, falls back to the handshake
// target and the client reports "REALITY: processed invalid connection".
func realitySealAuth(hello *utls.PubClientHelloMsg, authKey []byte) error {
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return fmt.Errorf("REALITY: build AES block: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("REALITY: build AES-GCM: %w", err)
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	return nil
}

// dropHybridKeyShare removes the post-quantum X25519MLKEM768 group from the
// ClientHello: both its key share entry and its supported_groups entry.
//
// REALITY encrypts its authentication payload into the ClientHello before the
// server chooses a key share, so the client has to keep the negotiated group
// deterministic: the payload is sealed with the classic X25519 key share, while
// a server that negotiates the hybrid X25519MLKEM768 group derives a different
// authentication key and treats the client as a probe. Post-quantum capable
// servers prefer that group as soon as the client advertises it (Go 1.24
// curvePreferences, Chrome 131+ parrots), which makes "chrome" fingerprints
// fail against them with "REALITY: processed invalid connection".
//
// Removing only the supported_groups entry is not enough: servers that validate
// key shares against the advertised groups reject the hello with
// "tls: illegal parameter". Removing both yields the pre-PQ Chrome hello shape
// that Xray's pinned uTLS fingerprints produce.
func dropHybridKeyShare(uConn *utls.UConn) {
	changed := false
	for _, ext := range uConn.Extensions {
		switch e := ext.(type) {
		case *utls.KeyShareExtension:
			kept := e.KeyShares[:0]
			for _, share := range e.KeyShares {
				if share.Group == utls.X25519MLKEM768 {
					changed = true
					continue
				}
				kept = append(kept, share)
			}
			e.KeyShares = kept
		case *utls.SupportedCurvesExtension:
			kept := e.Curves[:0]
			for _, curve := range e.Curves {
				if curve == utls.X25519MLKEM768 {
					changed = true
					continue
				}
				kept = append(kept, curve)
			}
			e.Curves = kept
		}
	}
	if !changed {
		return
	}
	if err := uConn.BuildHandshakeState(); err != nil {
		logger.Logger.WithError(err).Warn("REALITY: failed to rebuild ClientHello without X25519MLKEM768")
	}
}

// realityECDHEKey returns the TLS 1.3 ECDHE private key used by REALITY.
// Newer uTLS versions populate KeyShareKeys and may leave the deprecated
// EcdheKey field unset, so keep compatibility with both layouts.
func realityECDHEKey(state *utls.PubClientHandshakeState) *ecdh.PrivateKey {
	if state == nil {
		return nil
	}
	if keyShareKeys := state.State13.KeyShareKeys; keyShareKeys != nil {
		if keyShareKeys.Ecdhe != nil {
			return keyShareKeys.Ecdhe
		}
		if keyShareKeys.MlkemEcdhe != nil {
			return keyShareKeys.MlkemEcdhe
		}
	}
	return state.State13.EcdheKey // nolint:staticcheck
}

type RealityUConn struct {
	*utls.UConn
	ServerName string
	AuthKey    []byte
	Verified   bool
}

var p, _ = reflect.TypeFor[utls.Conn]().FieldByName("peerCertificates")

func (c *RealityUConn) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	certs := *(*[]*x509.Certificate)(unsafe.Add(unsafe.Pointer(c.Conn), p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.AuthKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.Verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

type Reality struct {
	protocol.StatelessDialer
	infoWriter io.Writer

	nextDialer  netproxy.Dialer
	serverName  string
	fingerprint *utls.ClientHelloID
	shortId     [8]byte
	publicKey   *ecdh.PublicKey
	spiderX     string
	spiderY     []int64

	// pqHybrid remembers whether this server authenticated with the
	// fingerprint's original ClientHello, which keeps the post-quantum
	// X25519MLKEM768 key share. Newest REALITY servers require that share and
	// answer as the real website when it is missing, while post-quantum aware
	// servers of the previous generation negotiate the hybrid group and then
	// derive a different REALITY authentication key, so both shapes exist in
	// the wild. The default shape is the pre-post-quantum one (see
	// dropHybridKeyShare); a failed handshake retries the other shape once.
	pqHybrid atomic.Bool
	// pqRetryAfter suppresses that second shape probe until this UNIX time once
	// both shapes failed, so a dead or blocked server is not dialled twice on
	// every single connection.
	pqRetryAfter atomic.Int64
}

func NewReality(s string, d netproxy.Dialer) (*Reality, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("NewReality: %w", err)
	}

	x := &Reality{
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: d,
		},
		nextDialer: d,
	}

	query := u.Query()
	x.serverName = query.Get("sni")
	if sidStr := query.Get("sid"); sidStr != "" {
		_, err := hex.Decode(x.shortId[:], []byte(sidStr))
		if err != nil {
			return nil, fmt.Errorf("invalid reality sid")
		}
	}
	_publicKey := query.Get("pbk")
	const x25519ScalarSize = 32
	var publicKey [x25519ScalarSize]byte
	_, err = base64.RawURLEncoding.Decode(publicKey[:], []byte(_publicKey))
	if err != nil {
		return nil, fmt.Errorf("invalid reality pbk")
	}
	x.publicKey, err = ecdh.X25519().NewPublicKey(publicKey[:])
	if err != nil {
		return nil, fmt.Errorf("REALITY: publicKey == nil: %w", err)
	}
	x.spiderX, _ = url.QueryUnescape(query.Get("spx"))
	_fingerprint := query.Get("fp")

	if x.serverName == "" {
		x.serverName = u.Hostname()
	} else if strings.ToLower(x.serverName) == "nosni" { // If ServerName is set to "nosni", we set it empty.
		x.serverName = ""
	}

	x.fingerprint, err = nameToUtlsClientHelloID(_fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get fingerprint: %w", err)
	}

	if x.spiderX == "" {
		x.spiderX = "/"
	}
	if x.spiderX[0] != '/' {
		return nil, fmt.Errorf(`invalid "spiderX": %v`, x.spiderX)
	}
	x.spiderY = make([]int64, 10)
	tmpU, _ := url.Parse(x.spiderX)
	q := tmpU.Query()
	parse := func(param string, index int) {
		if q.Get(param) != "" {
			s := strings.Split(q.Get(param), "-")
			if len(s) == 1 {
				x.spiderY[index], _ = strconv.ParseInt(s[0], 10, 64)
				x.spiderY[index+1], _ = strconv.ParseInt(s[0], 10, 64)
			} else {
				x.spiderY[index], _ = strconv.ParseInt(s[0], 10, 64)
				x.spiderY[index+1], _ = strconv.ParseInt(s[1], 10, 64)
			}
		}
		q.Del(param)
	}
	parse("p", 0) // padding
	parse("c", 2) // concurrency
	parse("t", 4) // times
	parse("i", 6) // interval
	parse("r", 8) // return
	u.RawQuery = q.Encode()
	x.spiderX = tmpU.String()
	return x, nil
}

func (x *Reality) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp":
		retry := 0
		retryHybrid := false
		hybridHello := x.pqHybrid.Load()
	retryHandshake:
		c, err = x.nextDialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("[REALITY]: dial to %s: %w", addr, err)
		}
		uConn := &RealityUConn{}
		utlsConfig := &utls.Config{
			VerifyPeerCertificate:  uConn.VerifyPeerCertificate,
			ServerName:             x.serverName,
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: true,
			KeyLogWriter:           x.infoWriter,
		}
		uConn.ServerName = utlsConfig.ServerName
		// Coalesce the TLS records of one write burst into one socket
		// write; the verified tunnel relays through this same conn.
		// BuildHandshakeState and the hello mutations below all happen in
		// memory before any write, so the coalescer never sees a partial
		// ClientHello. (Port of koutbound e3596a5.)
		co := coalesce.New(c)
		uConn.UConn = utls.UClient(co, utlsConfig, *x.fingerprint)
		{
			err = uConn.BuildHandshakeState()
			if err != nil {
				c.Close()
				return nil, err
			}
			hello := uConn.HandshakeState.Hello
			if !hybridHello {
				dropHybridKeyShare(uConn.UConn)
				hello = uConn.HandshakeState.Hello
			}
			hello.SessionId = make([]byte, 32)
			copy(hello.Raw[39:], hello.SessionId) // the fixed location of `Session ID`
			hello.SessionId[0] = Reality_Version_x
			hello.SessionId[1] = Reality_Version_y
			hello.SessionId[2] = Reality_Version_z
			hello.SessionId[3] = 0 // reserved
			binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
			copy(hello.SessionId[8:], x.shortId[:])
			ecdheKey := realityECDHEKey(&uConn.HandshakeState)
			if ecdheKey == nil {
				if retry >= realityHelloAttempts {
					c.Close()
					return nil, fmt.Errorf("REALITY: fingerprint %s %s does not provide a usable TLS 1.3 key share", x.fingerprint.Client, x.fingerprint.Version)
				}
				c.Close()
				retry++
				goto retryHandshake // rebuild the hello with a fresh key share
			}
			uConn.AuthKey, _ = ecdheKey.ECDH(x.publicKey)
			if uConn.AuthKey == nil {
				c.Close()
				return nil, errors.New("REALITY: SharedKey == nil")
			}
			if _, err := hkdf.New(sha256.New, uConn.AuthKey, hello.Random[:20], []byte("REALITY")).Read(uConn.AuthKey); err != nil {
				c.Close()
				return nil, err
			}
			if err := realitySealAuth(hello, uConn.AuthKey); err != nil {
				c.Close()
				return nil, err
			}
		}
		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		if !uConn.Verified {
			// The server answered as the real website instead of proving
			// itself, which means it rejected the REALITY authentication
			// payload. Retry once with the other ClientHello shape, because the
			// shape is what differs between server generations, then give up and
			// act as cover traffic.
			if !retryHybrid && (hybridHello || time.Now().Unix() >= x.pqRetryAfter.Load()) {
				retryHybrid = true
				hybridHello = !hybridHello
				_ = c.Close()
				// retryHandshake sits before the dial in this tree, so the
				// retry dials a fresh underlay; the close above prevents the
				// old one from leaking.
				goto retryHandshake
			}
			x.pqRetryAfter.Store(time.Now().Add(realityBothShapesBackoff).Unix())
			// Trigger spider.
			go func() {
				client := &http.Client{
					Transport: &http2.Transport{
						DialTLSContext: func(ctx context.Context, network, addr string, cfg *xtls.Config) (net.Conn, error) {
							return uConn, nil
						},
					},
				}
				prefix := []byte("https://" + uConn.ServerName)
				maps.Lock()
				if maps.maps == nil {
					maps.maps = make(map[string]map[string]bool)
				}
				paths := maps.maps[uConn.ServerName]
				if paths == nil {
					paths = make(map[string]bool)
					paths[x.spiderX] = true
					maps.maps[uConn.ServerName] = paths
				}
				firstURL := string(prefix) + getPathLocked(paths)
				maps.Unlock()
				get := func(first bool) {
					var (
						req  *http.Request
						resp *http.Response
						err  error
						body []byte
					)
					if first {
						req, _ = http.NewRequest("GET", firstURL, nil)
					} else {
						maps.Lock()
						req, _ = http.NewRequest("GET", string(prefix)+getPathLocked(paths), nil)
						maps.Unlock()
					}
					// Keep the spider request consistent with the impersonated
					// fingerprint: a Chrome ClientHello with a non-browser UA
					// (the old "Chrome" literal) is trivially linkable.
					ua.ApplyTo(req.Header, x.fingerprint)
					times := 1
					if !first {
						times = int(randBetween(x.spiderY[4], x.spiderY[5]))
					}
					for j := 0; j < times; j++ {
						if !first && j == 0 {
							req.Header.Set("Referer", firstURL)
						}
						req.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", int(randBetween(x.spiderY[0], x.spiderY[1])))})
						if resp, err = client.Do(req); err != nil {
							break
						}
						req.Header.Set("Referer", req.URL.String())
						if body, err = io.ReadAll(resp.Body); err != nil {
							break
						}
						maps.Lock()
						for _, m := range href.FindAllSubmatch(body, -1) {
							m[1] = bytes.TrimPrefix(m[1], prefix)
							if !bytes.Contains(m[1], dot) {
								paths[string(m[1])] = true
							}
						}
						req.URL.Path = getPathLocked(paths)
						maps.Unlock()
						if !first {
							time.Sleep(time.Duration(randBetween(x.spiderY[6], x.spiderY[7])) * time.Millisecond) // interval
						}
					}
				}
				get(true)
				concurrency := int(randBetween(x.spiderY[2], x.spiderY[3]))
				for range concurrency {
					go get(false)
				}
				// Do not close the connection
			}()
			time.Sleep(time.Duration(randBetween(x.spiderY[8], x.spiderY[9])) * time.Millisecond) // return
			return nil, errors.New("REALITY: processed invalid connection")
		}
		x.pqHybrid.Store(hybridHello)
		x.pqRetryAfter.Store(0)
		return coalesce.NewFlushConn(uConn, co), nil

	case "udp":
		return nil, fmt.Errorf("%w: Reality+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}

}

func (x *Reality) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return nil, fmt.Errorf("%w: Reality does not support UDP", netproxy.UnsupportedTunnelTypeError)
}

var (
	href = regexp.MustCompile(`href="([/h].*?)"`)
	dot  = []byte(".")
)

var maps struct {
	sync.Mutex
	maps map[string]map[string]bool
}

func getPathLocked(paths map[string]bool) string {
	stopAt := int(randBetween(0, int64(len(paths)-1)))
	i := 0
	for s := range paths {
		if i == stopAt {
			return s
		}
		i++
	}
	return "/"
}

func randBetween(left int64, right int64) int64 {
	if left == right {
		return left
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(right-left))
	return left + bigInt.Int64()
}
