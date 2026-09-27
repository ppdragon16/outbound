package tuic_test

import (
	"testing"

	tuiclink "github.com/daeuniverse/outbound/dialer/tuic"
)

func TestParseLiveLink(t *testing.T) {
	link := "tuic://0af4d518-315d-4980-be5f-22b6e1770d6a:0af4d518-315d-4980-be5f-22b6e1770d6a@[2400:8d60:3:0000:0000:1:8f5e:f9f0]:443?insecure=1&sni=www.linux.com&congestion_control=bbr&quicv2=1#evo_my_tui_v6"
	s, err := tuiclink.ParseTuicURL(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	t.Logf("user=%q pass=%q (len=%d)", s.User, s.Password, len(s.Password))
	t.Logf("server=%q port=%d sni=%q alpn=%v insecure=%v quicv2=%v cc=%q udp=%q",
		s.Server, s.Port, s.Sni, s.Alpn, s.AllowInsecure, s.QuicV2, s.CongestionControl, s.UdpRelayMode)
	if s.User != "0af4d518-315d-4980-be5f-22b6e1770d6a" {
		t.Errorf("UUID MISMATCH: %q", s.User)
	}
	if s.Password != "0af4d518-315d-4980-be5f-22b6e1770d6a" {
		t.Errorf("PASSWORD MISMATCH: %q (len %d)", s.Password, len(s.Password))
	}
}
