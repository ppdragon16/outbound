package tls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

type realityStubConn struct{}

var errRealityStubConnect = errors.New("reality hello test: no server")

func (realityStubConn) Read([]byte) (int, error)         { return 0, errRealityStubConnect }
func (realityStubConn) Write(b []byte) (int, error)      { return len(b), nil }
func (realityStubConn) Close() error                     { return nil }
func (realityStubConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (realityStubConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (realityStubConn) SetDeadline(time.Time) error      { return nil }
func (realityStubConn) SetReadDeadline(time.Time) error  { return nil }
func (realityStubConn) SetWriteDeadline(time.Time) error { return nil }

// helloExtension returns the body of the first extension of the given type.
func helloExtension(t *testing.T, raw []byte, extType uint16) []byte {
	t.Helper()
	// handshake header, legacy_version, random, session id, cipher suites,
	// compression methods, extensions length
	p := 4 + 2 + 32
	if p >= len(raw) {
		t.Fatalf("client hello too short: %d", len(raw))
	}
	p += 1 + int(raw[p])
	if p+2 > len(raw) {
		t.Fatalf("client hello truncated in cipher suites")
	}
	p += 2 + int(binary.BigEndian.Uint16(raw[p:]))
	if p >= len(raw) {
		t.Fatalf("client hello truncated in compression methods")
	}
	p += 1 + int(raw[p])
	if p+2 > len(raw) {
		t.Fatalf("client hello truncated in extensions")
	}
	end := p + 2 + int(binary.BigEndian.Uint16(raw[p:]))
	if end > len(raw) {
		t.Fatalf("client hello extension block overflows: %d > %d", end, len(raw))
	}
	for q := p + 2; q+4 <= end; {
		typ := binary.BigEndian.Uint16(raw[q:])
		length := int(binary.BigEndian.Uint16(raw[q+2:]))
		if typ == extType {
			return raw[q+4 : q+4+length]
		}
		q += 4 + length
	}
	return nil
}

func uint16List(t *testing.T, data []byte, listPrefix bool) []uint16 {
	t.Helper()
	if data == nil {
		return nil
	}
	if listPrefix {
		if len(data) < 2 {
			t.Fatalf("list extension too short")
		}
		data = data[2:]
	}
	var out []uint16
	for i := 0; i+1 < len(data); i += 2 {
		out = append(out, binary.BigEndian.Uint16(data[i:]))
	}
	return out
}

func hasUint16(values []uint16, want uint16) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func keyShareGroups(t *testing.T, raw []byte) []uint16 {
	t.Helper()
	data := helloExtension(t, raw, 51)
	if data == nil {
		t.Fatalf("client hello has no key_share extension")
	}
	if len(data) < 2 {
		t.Fatalf("key_share extension too short")
	}
	var out []uint16
	for q := 2; q+4 <= len(data); {
		out = append(out, binary.BigEndian.Uint16(data[q:]))
		q += 4 + int(binary.BigEndian.Uint16(data[q+2:]))
	}
	return out
}

func supportedGroups(t *testing.T, raw []byte) []uint16 {
	t.Helper()
	return uint16List(t, helloExtension(t, raw, 10), true)
}

func supportedVersions(t *testing.T, raw []byte) []uint16 {
	t.Helper()
	data := helloExtension(t, raw, 43)
	if data == nil {
		t.Fatalf("client hello has no supported_versions extension")
	}
	if len(data) < 1 {
		t.Fatalf("supported_versions extension too short")
	}
	// supported_versions carries a one-byte list length prefix.
	return uint16List(t, data[1:], false)
}

func buildStubHello(t *testing.T, id utls.ClientHelloID) *utls.UConn {
	t.Helper()
	uConn := utls.UClient(realityStubConn{}, &utls.Config{
		ServerName:         "www.microsoft.com",
		InsecureSkipVerify: true,
	}, id)
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatalf("%s/%s: build handshake state: %v", id.Client, id.Version, err)
	}
	return uConn
}

func TestDropHybridKeyShareRemovesPostQuantumGroup(t *testing.T) {
	for _, id := range []utls.ClientHelloID{utls.HelloChrome_Auto, utls.HelloChrome_133} {
		uConn := buildStubHello(t, id)
		before := append([]byte(nil), uConn.HandshakeState.Hello.Raw...)
		if !hasUint16(keyShareGroups(t, before), uint16(utls.X25519MLKEM768)) {
			t.Fatalf("%s/%s: expected a post-quantum key share to test", id.Client, id.Version)
		}

		dropHybridKeyShare(uConn)

		after := uConn.HandshakeState.Hello.Raw
		if hasUint16(keyShareGroups(t, after), uint16(utls.X25519MLKEM768)) {
			t.Fatalf("%s/%s: key_share still advertises X25519MLKEM768", id.Client, id.Version)
		}
		if hasUint16(supportedGroups(t, after), uint16(utls.X25519MLKEM768)) {
			t.Fatalf("%s/%s: supported_groups still advertises X25519MLKEM768", id.Client, id.Version)
		}
		// REALITY seals its authentication payload with the classic X25519 key
		// share, so it must survive the rewrite.
		if !hasUint16(keyShareGroups(t, after), uint16(utls.X25519)) {
			t.Fatalf("%s/%s: X25519 key share was removed", id.Client, id.Version)
		}
		if !hasUint16(supportedVersions(t, after), uint16(utls.VersionTLS13)) {
			t.Fatalf("%s/%s: TLS 1.3 was removed from supported_versions", id.Client, id.Version)
		}
		if got := len(uConn.HandshakeState.Hello.SessionId); got != 32 {
			t.Fatalf("%s/%s: session id length = %d, want 32", id.Client, id.Version, got)
		}
		if len(after) < 71 {
			t.Fatalf("%s/%s: rewritten hello too short for the REALITY session id: %d", id.Client, id.Version, len(after))
		}
		if uConn.HandshakeState.State13.KeyShareKeys == nil || uConn.HandshakeState.State13.KeyShareKeys.Ecdhe == nil {
			t.Fatalf("%s/%s: rewritten hello lost the X25519 key share keys", id.Client, id.Version)
		}
		if bytes.Equal(after, before) {
			t.Fatalf("%s/%s: hello was not rewritten", id.Client, id.Version)
		}
	}
}

func TestDropHybridKeyShareLeavesOtherFingerprintsUntouched(t *testing.T) {
	for _, id := range []utls.ClientHelloID{utls.HelloChrome_120, utls.HelloFirefox_120, utls.HelloSafari_Auto, utls.HelloIOS_Auto} {
		uConn := buildStubHello(t, id)
		before := append([]byte(nil), uConn.HandshakeState.Hello.Raw...)
		if hasUint16(keyShareGroups(t, before), uint16(utls.X25519MLKEM768)) {
			t.Fatalf("%s/%s: unexpected post-quantum key share in this fingerprint", id.Client, id.Version)
		}

		dropHybridKeyShare(uConn)

		if !bytes.Equal(uConn.HandshakeState.Hello.Raw, before) {
			t.Fatalf("%s/%s: hello changed without a post-quantum key share", id.Client, id.Version)
		}
	}
}
