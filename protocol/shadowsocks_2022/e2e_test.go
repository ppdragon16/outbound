package shadowsocks_2022_test

// True end-to-end coverage for the Shadowsocks-2022 (SIP022) client stack.
//
// The in-test server is an INDEPENDENT implementation of the wire format
// defined in Shadowsocks-NET/shadowsocks-specs (2022-1-shadowsocks-2022-
// edition): it is built directly on the spec primitives (BLAKE3 key
// derivation, AES-GCM / ChaCha20-Poly1305 AEADs) and intentionally does NOT
// call the client's own request-header pack/unpack helpers, so a shared
// framing bug cannot pass on both sides. The client is constructed exactly
// the way dialer/shadowsocks builds it: a direct dialer wrapped through
// protocol.NewDialer("shadowsocks_2022", ...).
//
// Covered here:
//   - TCP relay of >=4MiB, byte-exact, through a real loopback SIP022 server
//     (request salt + fixed-length header + length/payload chunks).
//   - Half-close: CloseWrite capability must survive the wrapper and EOF must
//     propagate target -> server -> client.
//   - UDP relay (framed session packets per §3.2/§4.1) against a real UDP
//     echo target, several datagrams, integrity + source address checks.
//   - Wrong PSK: the server derives different session keys and must produce
//     an error on the client (no panic, no hang).
//   - Many small writes AND one huge single write (chunk/buffer boundaries).

import (
	"bytes"
	"context"
	"crypto/aes"
	stdcipher "crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	protocol_direct "github.com/daeuniverse/outbound/protocol/direct"
	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

// ---- shared harness helpers (per-protocol e2e convention) ----

// loopbackEchoTarget starts a TCP echo server; everything received is sent
// back, and a peer half-close (FIN) is propagated back as EOF after the
// remaining output is flushed.
func loopbackEchoTarget(t *testing.T) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr()
}

// startUDPEchoTarget echoes datagrams back to their sender.
func startUDPEchoTarget(t *testing.T) net.Addr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr()
}

// e2eDeadlineCtx bounds every dial in the e2e so a hung protocol layer fails
// the test instead of hanging it.
func e2eDeadlineCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// e2eWantByte is the deterministic payload function used by every relay test:
// byte at absolute stream position pos of a stream seeded with seed.
func e2eWantByte(pos int, seed byte) byte {
	return seed + byte(pos*7)
}

// e2eVerifyReads reads exactly total bytes from c and checks them against the
// deterministic payload. Reading in modest pieces crosses chunk, record and
// buffer boundaries on purpose.
func e2eVerifyReads(t *testing.T, c net.Conn, total int, seed byte) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 32<<10)
	got := 0
	for got < total {
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read back at %d/%d: %v", got, total, err)
		}
		for i := 0; i < n; i++ {
			if want := e2eWantByte(got+i, seed); buf[i] != want {
				t.Fatalf("payload mismatch at %d: got %#x want %#x", got+i, buf[i], want)
			}
		}
		got += n
	}
}

// ---- in-test SIP022 server: independent wire-format implementation ----

const (
	ssHeaderTypeClient = 0 // HeaderTypeClientStream / HeaderTypeClientPacket
	ssHeaderTypeServer = 1 // HeaderTypeServerStream / HeaderTypeServerPacket
	ssNonceLen         = 12
	ssChunkMaxLen      = 0xFFFF
	ssTimestampWindow  = 30 * time.Second
	ssSessionInfo      = "shadowsocks 2022 session subkey"
)

// ssCipherSpec is the test server's own copy of the per-method parameters
// from the spec (§2.1 key/salt sizes, §4 chacha construction). It is derived
// from the spec text, not from the client's cipher table.
type ssCipherSpec struct {
	name    string
	keyLen  int  // PSK bytes
	saltLen int  // TCP request salt bytes
	aes     bool // true: §3 AES methods; false: §4 chacha20-poly1305
}

var ssCipherSpecs = []ssCipherSpec{
	{name: "2022-blake3-aes-128-gcm", keyLen: 16, saltLen: 16, aes: true},
	{name: "2022-blake3-aes-256-gcm", keyLen: 32, saltLen: 32, aes: true},
	// NOTE(ppdn port): chacha20-poly1305 is not in this fork's
	// ciphers.Aead2022CiphersConf, so it is not covered here.
}

// ssSubKey implements §2.2: blake3::derive_key("shadowsocks 2022 session
// subkey", psk + salt), with the subkey length equal to the PSK length.
func ssSubKey(psk, salt []byte) []byte {
	material := make([]byte, 0, len(psk)+len(salt))
	material = append(material, psk...)
	material = append(material, salt...)
	sub := make([]byte, len(psk))
	blake3.DeriveKey(sub, ssSessionInfo, material)
	return sub
}

// ssNewStreamAEAD builds the per-stream AEAD: AES-GCM for §3 methods,
// ChaCha20-Poly1305 (12-byte nonce) for §4 TCP.
func ssNewStreamAEAD(spec ssCipherSpec, key []byte) (stdcipher.AEAD, error) {
	if spec.aes {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return stdcipher.NewGCM(block)
	}
	return chacha20poly1305.New(key)
}

// ssIncNonce advances the u96 little-endian counter nonce (§3.1.1).
func ssIncNonce(nonce []byte) {
	for i := 0; i < len(nonce); i++ {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

func ssWithinTimestampWindow(ts time.Time, now time.Time) bool {
	diff := ts.Sub(now)
	if diff < 0 {
		diff = -diff
	}
	return diff <= ssTimestampWindow
}

// ssParseSocksAddr decodes ATYP + address + port from the front of b and
// returns the host:port and the number of bytes consumed.
func ssParseSocksAddr(b []byte) (host string, port uint16, consumed int, err error) {
	if len(b) < 1 {
		return "", 0, 0, io.ErrUnexpectedEOF
	}
	switch b[0] {
	case 1: // ipv4
		if len(b) < 7 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		return net.IP(b[1:5]).String(), binary.BigEndian.Uint16(b[5:7]), 7, nil
	case 4: // ipv6
		if len(b) < 19 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		return net.IP(b[1:17]).String(), binary.BigEndian.Uint16(b[17:19]), 19, nil
	case 3: // domain
		if len(b) < 2 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		return string(b[2 : 2+l]), binary.BigEndian.Uint16(b[2+l:]), 2 + l + 2, nil
	default:
		return "", 0, 0, fmt.Errorf("unsupported ATYP %d", b[0])
	}
}

// ssAppendSocksAddr encodes a loopback v4/v6 address as ATYP + address + port.
func ssAppendSocksAddr(dst []byte, ip net.IP, port int) []byte {
	if ip4 := ip.To4(); ip4 != nil {
		dst = append(dst, 1)
		dst = append(dst, ip4...)
	} else {
		dst = append(dst, 4)
		dst = append(dst, ip.To16()...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	return append(dst, portBytes[:]...)
}

// ssDrainClose implements the spec §3.1.3 guidance for rejected sessions:
// shut the write side first so a FIN instead of a RST is observed, drain what
// the peer still sends, then close. The bounds keep the test from hanging.
func ssDrainClose(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4096)
	for {
		if _, err := conn.Read(buf); err != nil {
			break
		}
	}
	_ = conn.Close()
}

func ssReadFullBounded(c net.Conn, buf []byte) error {
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	_, err := io.ReadFull(c, buf)
	return err
}

func ssWriteAllBounded(c net.Conn, buf []byte) error {
	if err := c.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	_, err := c.Write(buf)
	return err
}

// serveSS2022TCP handles one accepted conn as a SIP022 TCP server (§3.1):
// decrypt the request salt + fixed-length header + variable-length header
// with a server-side derivation, relay to the real target, and relay the
// target's reply back as a spec response stream (fresh salt, header echoing
// the request salt, then length/payload chunks). Half-close is propagated in
// both directions. With corruptResponseSalt the response header deliberately
// echoes a wrong request salt, which a spec-conformant client must reject.
func serveSS2022TCP(t *testing.T, spec ssCipherSpec, psk []byte, corruptResponseSalt bool, conn net.Conn) {
	t.Helper()
	defer conn.Close()

	// Request stream: salt, then the fixed-length header chunk (11 bytes
	// plaintext: type + u64be timestamp + u16be length).
	salt := make([]byte, spec.saltLen)
	if err := ssReadFullBounded(conn, salt); err != nil {
		return
	}
	reqAEAD, err := ssNewStreamAEAD(spec, ssSubKey(psk, salt))
	if err != nil {
		return
	}
	reqNonce := make([]byte, ssNonceLen)

	var fixedSealed [11 + 16]byte
	if err := ssReadFullBounded(conn, fixedSealed[:]); err != nil {
		return
	}
	fixed, err := reqAEAD.Open(nil, reqNonce, fixedSealed[:], nil)
	if err != nil {
		// Wrong PSK or corruption: the server cannot decrypt the request
		// header. Close per §3.1.3 without echoing anything.
		ssDrainClose(conn)
		return
	}
	ssIncNonce(reqNonce)
	if fixed[0] != ssHeaderTypeClient {
		return
	}
	if !ssWithinTimestampWindow(time.Unix(int64(binary.BigEndian.Uint64(fixed[1:9])), 0), time.Now()) {
		return
	}
	varLen := int(binary.BigEndian.Uint16(fixed[9:11]))
	if varLen < 7+2 || varLen > ssChunkMaxLen {
		// Smaller than an ipv4 address plus the padding-length field can
		// never hold a valid variable-length header.
		return
	}

	varSealed := make([]byte, varLen+16)
	if err := ssReadFullBounded(conn, varSealed); err != nil {
		return
	}
	varPlain, err := reqAEAD.Open(nil, reqNonce, varSealed, nil)
	if err != nil {
		ssDrainClose(conn)
		return
	}
	ssIncNonce(reqNonce)

	host, port, consumed, err := ssParseSocksAddr(varPlain)
	if err != nil {
		return
	}
	rest := varPlain[consumed:]
	if len(rest) < 2 {
		return
	}
	paddingLen := int(binary.BigEndian.Uint16(rest[:2]))
	initialPayload := rest[2+paddingLen:]
	// Spec §3.1.3: the server MUST reject a request whose variable-length
	// header contains neither padding nor initial payload.
	if paddingLen == 0 && len(initialPayload) == 0 {
		return
	}

	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 10*time.Second)
	if err != nil {
		return
	}
	defer target.Close()

	// The initial payload carried inside the request header is the start of
	// the proxied stream and must be forwarded to the target (§3.1.2).
	if len(initialPayload) > 0 {
		if _, err := target.Write(initialPayload); err != nil {
			return
		}
	}

	// Request relay (client -> target): length chunk + payload chunk pairs.
	// A clean EOF at a chunk boundary is the client's half-close and is
	// propagated to the target.
	go func() {
		for {
			var lenSealed [2 + 16]byte
			err := ssReadFullBounded(conn, lenSealed[:])
			if err != nil {
				if errors.Is(err, io.EOF) {
					if tc, ok := target.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
				}
				return
			}
			lenPlain, err := reqAEAD.Open(nil, reqNonce, lenSealed[:], nil)
			if err != nil {
				return
			}
			ssIncNonce(reqNonce)
			length := int(binary.BigEndian.Uint16(lenPlain))
			if length > ssChunkMaxLen {
				return
			}
			payloadSealed := make([]byte, length+16)
			if err := ssReadFullBounded(conn, payloadSealed); err != nil {
				return
			}
			payload, err := reqAEAD.Open(nil, reqNonce, payloadSealed, nil)
			if err != nil {
				return
			}
			ssIncNonce(reqNonce)
			if _, err := target.Write(payload); err != nil {
				return
			}
		}
	}()

	// Response stream (§3.1.2): fresh salt, one fixed-length header chunk
	// (type + timestamp + request salt + first chunk length) that doubles as
	// the first length chunk, then length/payload chunk pairs.
	respSalt := make([]byte, spec.saltLen)
	if _, err := crand.Read(respSalt); err != nil {
		return
	}
	respAEAD, err := ssNewStreamAEAD(spec, ssSubKey(psk, respSalt))
	if err != nil {
		return
	}
	respNonce := make([]byte, ssNonceLen)

	buf := make([]byte, 16<<10)
	_ = target.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err := target.Read(buf)
	if n == 0 {
		return
	}

	header := make([]byte, 0, 11+spec.saltLen)
	header = append(header, ssHeaderTypeServer)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().Unix()))
	header = append(header, ts[:]...)
	header = append(header, salt...)
	if corruptResponseSalt {
		// §3.1.3 requires the client to bind the response to its request by
		// checking this field; a flipped byte must be rejected by the client.
		header[len(header)-1] ^= 0xFF
	}
	var lenBytes [2]byte
	binary.BigEndian.PutUint16(lenBytes[:], uint16(n))
	header = append(header, lenBytes[:]...)

	frame := make([]byte, 0, spec.saltLen+len(header)+16+n+16)
	frame = append(frame, respSalt...)
	frame = respAEAD.Seal(frame, respNonce, header, nil)
	ssIncNonce(respNonce)
	frame = respAEAD.Seal(frame, respNonce, buf[:n], nil)
	ssIncNonce(respNonce)
	if err := ssWriteAllBounded(conn, frame); err != nil {
		return
	}

	for {
		_ = target.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := target.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint16(lenBytes[:], uint16(n))
			out := make([]byte, 0, 2+16+n+16)
			out = respAEAD.Seal(out, respNonce, lenBytes[:], nil)
			ssIncNonce(respNonce)
			out = respAEAD.Seal(out, respNonce, buf[:n], nil)
			ssIncNonce(respNonce)
			if err := ssWriteAllBounded(conn, out); err != nil {
				return
			}
		}
		if err != nil {
			// EOF from the target ends the response stream; closing the
			// client conn delivers EOF after everything already flushed.
			return
		}
	}
}

// startSS2022TCPServer runs the in-test SIP022 TCP server and returns its
// loopback address.
func startSS2022TCPServer(t *testing.T, spec ssCipherSpec, psk []byte) string {
	return startSS2022TCPServerOpts(t, spec, psk, false)
}

// startSS2022TCPServerOpts is startSS2022TCPServer with control over the
// response-header mutations used by the negative-path tests.
func startSS2022TCPServerOpts(t *testing.T, spec ssCipherSpec, psk []byte, corruptResponseSalt bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ss2022 listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSS2022TCP(t, spec, psk, corruptResponseSalt, c)
		}
	}()
	return ln.Addr().String()
}

// ssUDPServer is the in-test SIP022 UDP relay (§3.2 for AES methods, §4.1
// for chacha). Sessions are keyed by client session ID; every session owns a
// dedicated socket toward the target and a server-side session ID/packet ID
// pair for the return direction.
type ssUDPServer struct {
	spec ssCipherSpec
	psk  []byte

	conn *net.UDPConn

	mu       sync.Mutex
	sessions map[[8]byte]*ssUDPSession
	replayed atomic.Int64 // duplicate client packet IDs dropped (replay guard)
}

type ssUDPSession struct {
	mu         sync.Mutex
	srv        *ssUDPServer
	clientID   [8]byte
	serverID   [8]byte
	packetID   uint64
	seen       map[uint64]bool
	target     net.PacketConn
	clientAddr *net.UDPAddr
}

func startSS2022UDPServer(t *testing.T, spec ssCipherSpec, psk []byte) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ss2022 udp listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := &ssUDPServer{
		spec:     spec,
		psk:      psk,
		conn:     conn,
		sessions: make(map[[8]byte]*ssUDPSession),
	}
	go s.serve()
	return conn.LocalAddr().String()
}

func (s *ssUDPServer) serve() {
	buf := make([]byte, 65535)
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !s.handlePacket(buf[:n], from) {
			return
		}
	}
}

// ssUDPMessage is a decoded client-to-server datagram.
type ssUDPMessage struct {
	clientID [8]byte
	packetID uint64
	host     string
	port     int
	payload  []byte
}

func (s *ssUDPServer) decodePacket(pkt []byte) (*ssUDPMessage, bool) {
	if s.spec.aes {
		// §3.2.1/§3.2.2: AES-ECB separate header with the PSK, then an
		// AEAD body keyed by psk + separate_header[0:8] with nonce
		// separate_header[4:16].
		if len(pkt) < 16+16+11+7+2 { // sep header + tag + minimal header + addr
			return nil, false
		}
		block, err := aes.NewCipher(s.psk)
		if err != nil {
			return nil, false
		}
		sep := make([]byte, 16)
		block.Decrypt(sep, pkt[:16])
		var clientID [8]byte
		copy(clientID[:], sep[:8])
		aead, err := ssNewStreamAEAD(s.spec, ssSubKey(s.psk, sep[:8]))
		if err != nil {
			return nil, false
		}
		body, err := aead.Open(nil, sep[4:16], pkt[16:], nil)
		if err != nil {
			return nil, false
		}
		// §3.2.3 client-to-server header: type + timestamp + padding length
		// + padding + address (+ payload).
		if len(body) < 1+8+2+7 || body[0] != ssHeaderTypeClient {
			return nil, false
		}
		if !ssWithinTimestampWindow(time.Unix(int64(binary.BigEndian.Uint64(body[1:9])), 0), time.Now()) {
			return nil, false
		}
		paddingLen := int(binary.BigEndian.Uint16(body[9:11]))
		if 11+paddingLen > len(body) {
			return nil, false
		}
		host, port, consumed, err := ssParseSocksAddr(body[11+paddingLen:])
		if err != nil {
			return nil, false
		}
		payload := body[11+paddingLen+consumed:]
		return &ssUDPMessage{
			clientID: clientID,
			packetID: binary.BigEndian.Uint64(sep[8:16]),
			host:     host,
			port:     int(port),
			payload:  payload,
		}, true
	}

	// §4.1: XChaCha20-Poly1305 with the PSK directly and a random 24-byte
	// nonce; session ID + packet ID are merged into the message header.
	const nonceLen = 24
	if len(pkt) < nonceLen+16+8+8+1+8+2+7 {
		return nil, false
	}
	aead, err := chacha20poly1305.NewX(s.psk)
	if err != nil {
		return nil, false
	}
	body, err := aead.Open(nil, pkt[:nonceLen], pkt[nonceLen:], nil)
	if err != nil {
		return nil, false
	}
	var clientID [8]byte
	copy(clientID[:], body[:8])
	packetID := binary.BigEndian.Uint64(body[8:16])
	rest := body[16:]
	if len(rest) < 1+8+2+7 || rest[0] != ssHeaderTypeClient {
		return nil, false
	}
	if !ssWithinTimestampWindow(time.Unix(int64(binary.BigEndian.Uint64(rest[1:9])), 0), time.Now()) {
		return nil, false
	}
	paddingLen := int(binary.BigEndian.Uint16(rest[9:11]))
	if 11+paddingLen > len(rest) {
		return nil, false
	}
	host, port, consumed, err := ssParseSocksAddr(rest[11+paddingLen:])
	if err != nil {
		return nil, false
	}
	payload := rest[11+paddingLen+consumed:]
	return &ssUDPMessage{
		clientID: clientID,
		packetID: packetID,
		host:     host,
		port:     int(port),
		payload:  payload,
	}, true
}

func (s *ssUDPServer) handlePacket(pkt []byte, from *net.UDPAddr) bool {
	msg, ok := s.decodePacket(pkt)
	if !ok {
		return true // drop silently, keep serving
	}

	s.mu.Lock()
	sess, ok := s.sessions[msg.clientID]
	if !ok {
		target, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			s.mu.Unlock()
			return true
		}
		var serverID [8]byte
		if _, err := crand.Read(serverID[:]); err != nil {
			_ = target.Close()
			s.mu.Unlock()
			return true
		}
		sess = &ssUDPSession{
			srv:        s,
			clientID:   msg.clientID,
			serverID:   serverID,
			seen:       make(map[uint64]bool),
			target:     target,
			clientAddr: from,
		}
		s.sessions[msg.clientID] = sess
		go sess.pump()
	}
	// Sliding-window stand-in: reject duplicate packet IDs so a replayed or
	// forged datagram cannot pass for a second delivery.
	if sess.seen[msg.packetID] {
		s.mu.Unlock()
		s.replayed.Add(1)
		return true
	}
	sess.seen[msg.packetID] = true
	sess.clientAddr = from
	s.mu.Unlock()

	if _, err := sess.target.WriteTo(msg.payload, &net.UDPAddr{IP: net.ParseIP(msg.host), Port: msg.port}); err != nil {
		return true
	}
	return true
}

// pump relays datagrams from the session's target socket back to the client
// as spec server-to-client packets.
func (sess *ssUDPSession) pump() {
	s := sess.srv
	buf := make([]byte, 65535)
	for {
		_ = sess.target.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, from, err := sess.target.ReadFrom(buf)
		if err != nil {
			return
		}
		fromAddr, ok := from.(*net.UDPAddr)
		if !ok {
			return
		}
		sess.mu.Lock()
		sess.packetID++
		packetID := sess.packetID
		clientAddr := sess.clientAddr
		sess.mu.Unlock()

		var ts [8]byte
		binary.BigEndian.PutUint64(ts[:], uint64(time.Now().Unix()))

		var pkt []byte
		if s.spec.aes {
			// §3.2: encrypted separate header (server session ID + packet
			// ID) followed by the AEAD body. The body header additionally
			// carries the client session ID (§3.2.3).
			block, err := aes.NewCipher(s.psk)
			if err != nil {
				return
			}
			aead, err := ssNewStreamAEAD(s.spec, ssSubKey(s.psk, sess.serverID[:]))
			if err != nil {
				return
			}
			var sep [16]byte
			copy(sep[:8], sess.serverID[:])
			binary.BigEndian.PutUint64(sep[8:], packetID)
			var sepEnc [16]byte
			block.Encrypt(sepEnc[:], sep[:])

			body := make([]byte, 0, 1+8+8+2+19+n)
			body = append(body, ssHeaderTypeServer)
			body = append(body, ts[:]...)
			body = append(body, sess.clientID[:]...)
			body = append(body, 0, 0) // padding length
			body = ssAppendSocksAddr(body, fromAddr.IP, fromAddr.Port)
			body = append(body, buf[:n]...)
			pkt = aead.Seal(sepEnc[:], sep[4:16], body, nil)
		} else {
			// §4.1: random 24-byte nonce; server session ID + packet ID +
			// client session ID merged into the header.
			aead, err := chacha20poly1305.NewX(s.psk)
			if err != nil {
				return
			}
			nonce := make([]byte, 24)
			if _, err := crand.Read(nonce); err != nil {
				return
			}
			body := make([]byte, 0, 8+8+1+8+8+2+19+n)
			body = append(body, sess.serverID[:]...)
			var pid [8]byte
			binary.BigEndian.PutUint64(pid[:], packetID)
			body = append(body, pid[:]...)
			body = append(body, ssHeaderTypeServer)
			body = append(body, ts[:]...)
			body = append(body, sess.clientID[:]...)
			body = append(body, 0, 0) // padding length
			body = ssAppendSocksAddr(body, fromAddr.IP, fromAddr.Port)
			body = append(body, buf[:n]...)
			pkt = aead.Seal(nonce, nonce, body, nil)
		}

		sess.mu.Lock()
		conn := s.conn
		sess.mu.Unlock()
		if _, err := conn.WriteToUDP(pkt, clientAddr); err != nil {
			return
		}
	}
}

// ---- client construction (exactly the dialer/shadowsocks consumer path) ----

// newSS2022ClientDialer builds the dae-side dialer the way
// dialer/shadowsocks does for cipher names in the 2022 family:
// direct -> protocol.NewDialer("shadowsocks_2022", ...).
func newSS2022ClientDialer(t *testing.T, proxyAddr, cipherName, pskBase64 string) netproxy.Dialer {
	t.Helper()
	protocol_direct.InitDirectDialers("", false, 0)
	ddirect := protocol_direct.Direct
	d, err := protocol.NewDialer("shadowsocks_2022", ddirect, protocol.Header{
		ProxyAddress: proxyAddr,
		Cipher:       cipherName,
		Password:     pskBase64,
	})
	if err != nil {
		t.Fatalf("shadowsocks_2022 dialer: %v", err)
	}
	return d
}

// randomPSKBase64 returns a cryptographically random PSK, base64-encoded the
// way users provide it (openssl rand -base64 <key_size>).
func randomPSKBase64(t *testing.T, keyLen int) string {
	t.Helper()
	psk := make([]byte, keyLen)
	if _, err := crand.Read(psk); err != nil {
		t.Fatalf("psk: %v", err)
	}
	return base64.StdEncoding.EncodeToString(psk)
}

// ---- the e2e tests ----

// TestE2ESS2022TCPRelay pushes 4MiB through client -> SIP022 server -> echo
// target -> back on a real loopback socket, byte-exact, then half-closes and
// expects EOF propagation. Losing the CloseWrite capability in a wrapper must
// fail this e2e instead of silently skipping the check.
func TestE2ESS2022TCPRelay(t *testing.T) {
	for _, spec := range ssCipherSpecs {
		t.Run(spec.name, func(t *testing.T) {
			echoAddr := loopbackEchoTarget(t)
			psk := randomPSKBase64(t, spec.keyLen)
			pskRaw, err := base64.StdEncoding.DecodeString(psk)
			if err != nil {
				t.Fatalf("psk decode: %v", err)
			}
			proxyAddr := startSS2022TCPServer(t, spec, pskRaw)
			d := newSS2022ClientDialer(t, proxyAddr, spec.name, psk)

			c, err := d.DialContext(e2eDeadlineCtx(t), "tcp", echoAddr.String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()

			total := 4 << 20
			seed := byte(0x5A)
			done := make(chan error, 1)
			go func() {
				done <- func() error {
					buf := make([]byte, 64<<10)
					sent := 0
					for sent < total {
						n := len(buf)
						if total-sent < n {
							n = total - sent
						}
						for i := 0; i < n; i++ {
							buf[i] = e2eWantByte(sent+i, seed)
						}
						if err := c.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
							return err
						}
						if _, err := c.Write(buf[:n]); err != nil {
							return err
						}
						sent += n
					}
					return nil
				}()
			}()
			e2eVerifyReads(t, c, total, seed)
			if err := <-done; err != nil {
				t.Fatalf("send: %v", err)
			}

			closeWrite, ok := c.(interface{ CloseWrite() error })
			if !ok {
				t.Fatalf("shadowsocks_2022 conn %T lost the CloseWrite capability", c)
			}
			if err := closeWrite.CloseWrite(); err != nil {
				t.Fatalf("CloseWrite: %v", err)
			}
			if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			buf := make([]byte, 1024)
			n, err := c.Read(buf)
			if n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("read after half-close = %d, %v, want 0, EOF", n, err)
			}
		})
	}
}

// TestE2ESS2022TCPWritePatterns covers buffer/chunk boundaries: many small
// writes and one huge single write, both byte-exact through the echo target.
func TestE2ESS2022TCPWritePatterns(t *testing.T) {
	for _, spec := range ssCipherSpecs {
		t.Run(spec.name, func(t *testing.T) {
			echoAddr := loopbackEchoTarget(t)
			psk := randomPSKBase64(t, spec.keyLen)
			pskRaw, err := base64.StdEncoding.DecodeString(psk)
			if err != nil {
				t.Fatalf("psk decode: %v", err)
			}
			proxyAddr := startSS2022TCPServer(t, spec, pskRaw)
			d := newSS2022ClientDialer(t, proxyAddr, spec.name, psk)

			c, err := d.DialContext(e2eDeadlineCtx(t), "tcp", echoAddr.String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()

			// Many small writes: every steady-state chunk path, including
			// 1-byte writes.
			small := make([]int, 0, 512)
			pattern := []int{1, 13, 127, 1024, 1500, 2, 999}
			for i := 0; i < 512; i++ {
				small = append(small, pattern[i%len(pattern)])
			}
			// One huge write: far beyond the 0xFFFF chunk cap, so the first
			// write's initial payload clamping and multi-chunk framing of a
			// single Write call are both exercised.
			sizes := append(small, 300_000)
			total := 0
			for _, size := range sizes {
				total += size
			}

			done := make(chan error, 1)
			go func() {
				done <- func() error {
					seed := byte(0xA5)
					buf := make([]byte, 0, 300_000)
					pos := 0
					for _, size := range sizes {
						buf = buf[:size]
						for i := range buf {
							buf[i] = e2eWantByte(pos+i, seed)
						}
						if err := c.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
							return err
						}
						if _, err := c.Write(buf); err != nil {
							return err
						}
						pos += size
					}
					return nil
				}()
			}()
			e2eVerifyReads(t, c, total, 0xA5)
			if err := <-done; err != nil {
				t.Fatalf("send: %v", err)
			}
		})
	}
}

// TestE2ESS2022ResponseSaltMismatchIsRejected covers the §3.1.3 client MUST:
// the response fixed-length header echoes the request salt and the client
// must reject a response whose echoed salt does not match its own request.
// A server cannot be tricked into decrypting a response that was not made
// for this request stream.
func TestE2ESS2022ResponseSaltMismatchIsRejected(t *testing.T) {
	for _, spec := range ssCipherSpecs {
		t.Run(spec.name, func(t *testing.T) {
			echoAddr := loopbackEchoTarget(t)
			psk := randomPSKBase64(t, spec.keyLen)
			pskRaw, err := base64.StdEncoding.DecodeString(psk)
			if err != nil {
				t.Fatalf("psk decode: %v", err)
			}
			proxyAddr := startSS2022TCPServerOpts(t, spec, pskRaw, true)
			d := newSS2022ClientDialer(t, proxyAddr, spec.name, psk)

			c, err := d.DialContext(e2eDeadlineCtx(t), "tcp", echoAddr.String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()

			if err := c.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatalf("SetWriteDeadline: %v", err)
			}
			if _, err := c.Write([]byte("hello")); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			buf := make([]byte, 128)
			n, err := c.Read(buf)
			if err == nil {
				t.Fatalf("client accepted a response with a mismatched request salt (%d bytes: %q)", n, buf[:n])
			}
		})
	}
}

// TestE2ESS2022UDPRelay exercises the UDP session path against a real UDP
// echo target: several datagrams of varying size, integrity and source
// address checked per §3.2 (AES) / §4.1 (chacha).
func TestE2ESS2022UDPRelay(t *testing.T) {
	for _, spec := range ssCipherSpecs {
		t.Run(spec.name, func(t *testing.T) {
			udpEcho := startUDPEchoTarget(t)
			psk := randomPSKBase64(t, spec.keyLen)
			pskRaw, err := base64.StdEncoding.DecodeString(psk)
			if err != nil {
				t.Fatalf("psk decode: %v", err)
			}
			proxyAddr := startSS2022UDPServer(t, spec, pskRaw)
			d := newSS2022ClientDialer(t, proxyAddr, spec.name, psk)

			pc, err := d.DialContext(e2eDeadlineCtx(t), "udp", udpEcho.String())
			if err != nil {
				t.Fatalf("dial udp: %v", err)
			}
			defer pc.Close()

			packetConn, ok := pc.(net.PacketConn)
			if !ok {
				t.Fatalf("DialContext(udp) returned %T, want a PacketConn", pc)
			}
			for i := 0; i < 16; i++ {
				payload := make([]byte, 200+i*77)
				for j := range payload {
					payload[j] = byte(i + j)
				}
				if err := pc.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
					t.Fatalf("SetWriteDeadline: %v", err)
				}
				n, err := packetConn.WriteTo(payload, udpEcho)
				if err != nil {
					t.Fatalf("WriteTo: %v", err)
				}
				if n != len(payload) {
					t.Fatalf("WriteTo = %d, want %d", n, len(payload))
				}
				buf := make([]byte, 4096)
				if err := pc.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
					t.Fatalf("SetReadDeadline: %v", err)
				}
				rn, from, err := packetConn.ReadFrom(buf)
				if err != nil {
					t.Fatalf("ReadFrom: %v", err)
				}
				if rn != len(payload) || !bytes.Equal(buf[:rn], payload) {
					t.Fatalf("datagram %d mismatch: n=%d want=%d", i, rn, len(payload))
				}
				if from.String() != udpEcho.String() {
					t.Fatalf("datagram %d source = %v, want %v", i, from, udpEcho.String())
				}
			}
		})
	}
}

// TestE2ESS2022WrongPSKIsAnErrorNotAPanic points the client at a server
// holding a different PSK: the server derives different session keys, fails
// to open the request header and closes; the client must surface an error
// instead of hanging or panicking.
func TestE2ESS2022WrongPSKIsAnErrorNotAPanic(t *testing.T) {
	for _, spec := range ssCipherSpecs {
		t.Run(spec.name, func(t *testing.T) {
			echoAddr := loopbackEchoTarget(t)
			serverPSK := randomPSKBase64(t, spec.keyLen)
			serverPSKRaw, err := base64.StdEncoding.DecodeString(serverPSK)
			if err != nil {
				t.Fatalf("psk decode: %v", err)
			}
			proxyAddr := startSS2022TCPServer(t, spec, serverPSKRaw)
			clientPSK := randomPSKBase64(t, spec.keyLen)
			d := newSS2022ClientDialer(t, proxyAddr, spec.name, clientPSK)

			c, err := d.DialContext(e2eDeadlineCtx(t), "tcp", echoAddr.String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()

			if err := c.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatalf("SetWriteDeadline: %v", err)
			}
			_, _ = c.Write([]byte("hello"))
			if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			buf := make([]byte, 128)
			for i := 0; i < 20; i++ {
				if _, err := c.Read(buf); err != nil {
					return // an error surfaced: pass
				}
				time.Sleep(50 * time.Millisecond)
			}
			t.Fatal("server rejected the session but the client never surfaced an error")
		})
	}
}
