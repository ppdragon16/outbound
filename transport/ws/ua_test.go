package ws

import (
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
)

func wsDialerFor(t *testing.T, imitate string) *Ws {
	t.Helper()
	cfg := &WsConfig{
		Scheme:   "wss",
		Host:     "example.com:443",
		Path:     "/",
		Hostname: "example.com",
		Sni:      "example.com",
	}
	d, err := cfg.Dialer(&dialer.ExtraOption{TlsImplementation: "utls", UtlsImitate: imitate}, nil)
	if err != nil {
		t.Fatalf("Dialer: %v", err)
	}
	return d.(*Ws)
}

// TestWsHeadersMatchFingerprint covers B5 on the WebSocket transport: the
// cleartext handshake must carry the User-Agent and browser headers of the
// fingerprint being impersonated, otherwise the two layers contradict each
// other (a Chrome JA3 with a Go default UA is trivially linkable).
func TestWsHeadersMatchFingerprint(t *testing.T) {
	w := wsDialerFor(t, "chrome_102")
	ua := w.header.Get("User-Agent")
	if ua == "" || !strings.Contains(ua, "Chrome/102.0.0.0") {
		t.Fatalf("User-Agent should carry the impersonated Chrome version, got %q", ua)
	}
	if strings.Contains(ua, "Go-http-client") {
		t.Fatalf("Go default UA leaked: %q", ua)
	}
	if w.header.Get("Accept-Language") == "" {
		t.Fatal("browser Accept-Language missing")
	}
	if w.header.Get("Sec-Ch-Ua") == "" {
		t.Fatal("Chromium fingerprint should send Sec-CH-UA")
	}
	// The Host header of the upgrade request must survive the header merge.
	if w.header.Get("Host") != "example.com" {
		t.Fatalf("Host header clobbered: %q", w.header.Get("Host"))
	}
}

func TestWsHeadersFirefoxHasNoClientHints(t *testing.T) {
	w := wsDialerFor(t, "firefox_105")
	if ua := w.header.Get("User-Agent"); !strings.Contains(ua, "Firefox/105.0") {
		t.Fatalf("expected a Firefox UA, got %q", ua)
	}
	if w.header.Get("Sec-Ch-Ua") != "" {
		t.Fatal("Firefox must not send Chromium client hints")
	}
}

// TestWsHeadersFallBackWithoutFingerprint covers the "no fingerprint context"
// path (unknown or empty utls_imitate): headers must still be browser-like
// rather than the Go default.
func TestWsHeadersFallBackWithoutFingerprint(t *testing.T) {
	w := wsDialerFor(t, "")
	if ua := w.header.Get("User-Agent"); ua == "" || strings.Contains(ua, "Go-http-client") {
		t.Fatalf("fallback UA must be browser-like, got %q", ua)
	}
}

// TestWsNoOriginOrReferer guards against injecting headers that servers may
// validate; a wrong Origin would break the handshake.
func TestWsNoOriginOrReferer(t *testing.T) {
	w := wsDialerFor(t, "chrome_102")
	for _, k := range []string{"Origin", "Referer"} {
		if w.header.Get(k) != "" {
			t.Fatalf("%s must not be derived automatically", k)
		}
	}
}
