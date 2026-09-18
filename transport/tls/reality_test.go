package tls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func mustGenerateX25519Key(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate x25519 key: %v", err)
	}
	return key
}

func TestRealityECDHEKeyPrefersKeyShareKeysEcdhe(t *testing.T) {
	key := mustGenerateX25519Key(t)
	state := &utls.PubClientHandshakeState{
		State13: utls.TLS13OnlyState{
			KeyShareKeys: &utls.KeySharePrivateKeys{
				Ecdhe: key,
			},
		},
	}

	if got := realityECDHEKey(state); got != key {
		t.Fatalf("expected key from KeyShareKeys.Ecdhe")
	}
}

func TestRealityECDHEKeyFallsBackToMlkemEcdhe(t *testing.T) {
	key := mustGenerateX25519Key(t)
	state := &utls.PubClientHandshakeState{
		State13: utls.TLS13OnlyState{
			KeyShareKeys: &utls.KeySharePrivateKeys{
				MlkemEcdhe: key,
			},
		},
	}

	if got := realityECDHEKey(state); got != key {
		t.Fatalf("expected key from KeyShareKeys.MlkemEcdhe")
	}
}

func TestRealityECDHEKeyFallsBackToDeprecatedField(t *testing.T) {
	key := mustGenerateX25519Key(t)
	state := &utls.PubClientHandshakeState{
		State13: utls.TLS13OnlyState{
			EcdheKey: key,
		},
	}

	if got := realityECDHEKey(state); got != key {
		t.Fatalf("expected key from deprecated EcdheKey field")
	}
}

// A REALITY server opens the client auth payload with AES-GCM no matter
// which cipher suites the fingerprint offers. Regression: the client used to
// seal with ChaCha20-Poly1305 whenever the first recognized offered suite was
// not AES-GCM, which randomized fingerprints (fp=random, fp=randomized) hit on
// a fraction of dials; the server then answered "REALITY: processed invalid
// connection".
func TestRealitySealAuthUsesAESGCMRegardlessOfCipherSuites(t *testing.T) {
	authKey := make([]byte, 32)
	for i := range authKey {
		authKey[i] = byte(i + 1)
	}
	hello := &utls.PubClientHelloMsg{
		Raw:          make([]byte, 128),
		Random:       make([]byte, 32),
		SessionId:    make([]byte, 32),
		CipherSuites: []uint16{utls.TLS_CHACHA20_POLY1305_SHA256, utls.TLS_AES_128_GCM_SHA256},
	}
	for i := range hello.Random {
		hello.Random[i] = byte(0x40 + i)
	}
	// Client plaintext layout: [0:3] version, [3] reserved, [4:8] timestamp,
	// [8:16] short ID.
	hello.SessionId[0], hello.SessionId[1], hello.SessionId[2] = 1, 8, 10
	binary.BigEndian.PutUint32(hello.SessionId[4:], 0x11223344)
	copy(hello.SessionId[8:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	wantPayload := append([]byte(nil), hello.SessionId[:16]...)

	if err := realitySealAuth(hello, authKey); err != nil {
		t.Fatalf("seal REALITY auth: %v", err)
	}
	if !bytes.Equal(hello.Raw[39:71], hello.SessionId) {
		t.Fatal("sealed session ID was not copied into the raw ClientHello")
	}

	// Server side: lift the ciphertext out of the ClientHello, clear the
	// session ID in place, then open the payload with AES-128-GCM. The server
	// never consults the offered cipher suites.
	ciphertext := append([]byte(nil), hello.Raw[39:71]...)
	clear(hello.Raw[39:71])
	block, err := aes.NewCipher(authKey)
	if err != nil {
		t.Fatalf("build AES block: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("build AES-GCM: %v", err)
	}
	got, err := aead.Open(nil, hello.Random[20:], ciphertext, hello.Raw)
	if err != nil {
		t.Fatalf("server could not open REALITY auth payload with AES-GCM: %v", err)
	}
	if !bytes.Equal(got, wantPayload) {
		t.Fatalf("auth payload mismatch: got %x want %x", got, wantPayload)
	}
}
