package protocol

import (
	"testing"

	"github.com/daeuniverse/quic-go"
)

func TestQuicVersions(t *testing.T) {
	if got := QuicVersions(0); got != nil {
		t.Fatalf("default must leave the QUIC stack default order, got %v", got)
	}
	got := QuicVersions(Flags_Quic_PreferV2)
	if len(got) != 2 || got[0] != quic.Version2 || got[1] != quic.Version1 {
		t.Fatalf("preferV2 order = %v, want [v2 v1]", got)
	}
	// unrelated flags must not flip the preference
	if got := QuicVersions(Flags_VMess_UsePacketAddr); got != nil {
		t.Fatalf("unrelated flag changed versions: %v", got)
	}
	// HTTP/3 dialers must stay single-version
	if got := QuicVersionsHTTP3(0); got != nil {
		t.Fatalf("http3 default must stay nil (http3 fills [v1]), got %v", got)
	}
	if got := QuicVersionsHTTP3(Flags_Quic_PreferV2); len(got) != 1 || got[0] != quic.Version2 {
		t.Fatalf("http3 preferV2 = %v, want [v2]", got)
	}

	// the flag must not collide with the existing iota groups
	if Flags_Quic_PreferV2 == Flags_VMess_UsePacketAddr || Flags_Quic_PreferV2 == Flags_Tuic_UdpRelayModeQuic {
		t.Fatal("Flags_Quic_PreferV2 collides with an existing flag bit")
	}
}
