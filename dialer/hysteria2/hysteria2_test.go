package hysteria2

import "testing"

func TestHysteria2URLQuicV2(t *testing.T) {
	parsed, err := ParseHysteria2URL("hysteria2://pass@example.com:443?quic_version=2")
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.QuicV2 {
		t.Fatal("quic_version=2 must enable QUIC v2")
	}
	exported := parsed.ExportToURL()
	reparsed, err := ParseHysteria2URL(exported)
	if err != nil {
		t.Fatal(err)
	}
	if !reparsed.QuicV2 {
		t.Fatalf("round trip lost quic_version: %q", exported)
	}

	off, err := ParseHysteria2URL("hysteria2://pass@example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if off.QuicV2 {
		t.Fatal("QUIC v2 must be opt-in")
	}
}
