package protocol

import "github.com/daeuniverse/quic-go"

// QuicVersions returns the QUIC version preference list for an outbound
// handshake. With Flags_Quic_PreferV2 set the first packet uses QUIC v2
// (RFC 9369, version 0x6b3343cf) with v1 kept for version-negotiation
// fallback; otherwise nil is returned so the QUIC stack keeps its default
// order (v1 first, RFC 9000).
//
// Offering v2 first is what breaks middleboxes that pinned the single-version
// 0x00000001 long-header pattern, so it is opt-in per outbound.
func QuicVersions(flags Flags) []quic.Version {
	if flags&Flags_Quic_PreferV2 == 0 {
		return nil
	}
	return []quic.Version{quic.Version2, quic.Version1}
}

// QuicVersionsHTTP3 returns the QUIC version list for outbounds that dial their
// HTTP/3 layer through quic-go's http3.Transport (hysteria2's auth round trip).
// That dialer rejects multi-version configs, so preferring v2 here means
// pinning v2 without negotiation fallback; leaving it nil lets http3 fill in
// its own single version (v1).
func QuicVersionsHTTP3(flags Flags) []quic.Version {
	if flags&Flags_Quic_PreferV2 == 0 {
		return nil
	}
	return []quic.Version{quic.Version2}
}
