package juicity

import "testing"

func TestJuicityURLQuicV2(t *testing.T) {
	parsed, err := ParseJuicityURL("juicity://uuid:pass@example.com:443?quic_version=2")
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.QuicV2 {
		t.Fatal("quic_version=2 must enable QUIC v2")
	}
	exported := parsed.ExportToURL()
	reparsed, err := ParseJuicityURL(exported)
	if err != nil {
		t.Fatal(err)
	}
	if !reparsed.QuicV2 {
		t.Fatalf("round trip lost quic_version: %q", exported)
	}

	off, err := ParseJuicityURL("juicity://uuid:pass@example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if off.QuicV2 {
		t.Fatal("QUIC v2 must be opt-in")
	}
}
