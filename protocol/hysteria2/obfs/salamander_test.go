package obfs

import (
	"bytes"
	"testing"
)

func TestSalamanderRoundTrip(t *testing.T) {
	psk := []byte("cry_me_a_river")
	ob, err := newSalamanderObfuscator(psk)
	if err != nil {
		t.Fatalf("newSalamanderObfuscator: %v", err)
	}
	payload := []byte("hello hy2 obfs world, this payload is longer than the salt")
	wire := make([]byte, len(payload)+smSaltLen)
	plain := make([]byte, len(payload))

	if n := ob.Obfuscate(payload, wire); n != len(payload)+smSaltLen {
		t.Fatalf("Obfuscate length = %d, want %d", n, len(payload)+smSaltLen)
	}
	if bytes.Equal(wire[smSaltLen:], payload) {
		t.Fatal("payload not obfuscated (identical to plaintext)")
	}
	if n := ob.Deobfuscate(wire, plain); n != len(payload) {
		t.Fatalf("Deobfuscate length = %d, want %d", n, len(payload))
	}
	if !bytes.Equal(plain, payload) {
		t.Fatalf("round trip mismatch: got %q want %q", plain, payload)
	}
}

func TestSalamanderSaltUniqueness(t *testing.T) {
	ob, err := newSalamanderObfuscator([]byte("psk1"))
	if err != nil {
		t.Fatalf("newSalamanderObfuscator: %v", err)
	}
	payload := []byte("same payload")
	w1 := make([]byte, len(payload)+smSaltLen)
	w2 := make([]byte, len(payload)+smSaltLen)
	ob.Obfuscate(payload, w1)
	ob.Obfuscate(payload, w2)
	if bytes.Equal(w1, w2) {
		t.Fatal("two obfuscations of same payload produced identical output (salt not random?)")
	}
}

func TestSalamanderPSKTooShort(t *testing.T) {
	if _, err := newSalamanderObfuscator([]byte("ab")); err == nil {
		t.Fatal("expected ErrPSKTooShort for 2-byte PSK")
	}
}

func TestSalamanderInvalidPacket(t *testing.T) {
	ob, err := newSalamanderObfuscator([]byte("psk1"))
	if err != nil {
		t.Fatalf("newSalamanderObfuscator: %v", err)
	}
	out := make([]byte, 16)
	if n := ob.Deobfuscate([]byte("short"), out); n != 0 {
		t.Fatalf("Deobfuscate of packet shorter than salt should return 0, got %d", n)
	}
}
