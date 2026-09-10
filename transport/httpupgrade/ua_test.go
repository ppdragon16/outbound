package httpupgrade

import (
	"net/http"
	"strings"
	"testing"
)

// TestHTTPUpgradeHeadersMatchFingerprint covers B5 on the HTTPUpgrade
// transport: the upgrade request must carry the headers of the impersonated
// fingerprint instead of the Go default UA.
func TestHTTPUpgradeHeadersMatchFingerprint(t *testing.T) {
	d, err := NewDialer("https://example.com/?host=example.com&path=/up", nil)
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	d.UseFingerprintName("chrome_102")

	if d.headers == nil {
		t.Fatal("fingerprint headers were not derived")
	}
	ua := d.headers.Get("User-Agent")
	if !strings.Contains(ua, "Chrome/102.0.0.0") {
		t.Fatalf("User-Agent should carry the impersonated Chrome version, got %q", ua)
	}
	if d.headers.Get("Accept-Language") == "" {
		t.Fatal("browser Accept-Language missing")
	}
}

// TestHTTPUpgradeDefaultHeadersWithoutFingerprint covers the fallback: an
// unknown or empty fingerprint name still yields browser-like headers rather
// than the Go default.
func TestHTTPUpgradeDefaultHeadersWithoutFingerprint(t *testing.T) {
	d, err := NewDialer("https://example.com/?host=example.com&path=/up", nil)
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	d.UseFingerprintName("definitely_not_a_fingerprint")

	ua := d.headers.Get("User-Agent")
	if ua == "" || strings.Contains(ua, "Go-http-client") {
		t.Fatalf("fallback UA must be browser-like, got %q", ua)
	}
}

// TestHTTPUpgradeHandshakeHeadersAreBrowserLike asserts the property that
// matters on the wire: Connection/Upgrade stay intact while browser headers are
// merged in, and no Origin/Referer is invented.
func TestHTTPUpgradeHandshakeHeadersAreBrowserLike(t *testing.T) {
	req, err := http.NewRequest("GET", "/up", nil)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDialer("https://example.com/?host=example.com&path=/up", nil)
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	d.UseFingerprintName("chrome_102")

	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	headers := d.headers
	if headers == nil {
		headers = http.Header{}
	}
	for k, v := range headers {
		req.Header[k] = v
	}

	if req.Header.Get("Connection") != "upgrade" || req.Header.Get("Upgrade") != "websocket" {
		t.Fatal("handshake headers must survive the merge")
	}
	if req.Header.Get("User-Agent") == "" {
		t.Fatal("User-Agent missing from the handshake")
	}
	for _, k := range []string{"Origin", "Referer"} {
		if req.Header.Get(k) != "" {
			t.Fatalf("%s must not be derived automatically", k)
		}
	}
}
