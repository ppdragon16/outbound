package ua

import (
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestUserAgentMatchesFingerprint(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   *utls.ClientHelloID
		want []string
	}{
		{"chrome_133", &utls.HelloChrome_133, []string{"Chrome/133.0.0.0"}},
		{"chrome_auto", &utls.HelloChrome_Auto, []string{"Chrome/133.0.0.0"}},
		{"chrome_psk_suffix", &utls.HelloChrome_100_PSK, []string{"Chrome/100.0.0.0"}},
		{"chrome_pq_suffix", &utls.HelloChrome_115_PQ, []string{"Chrome/115.0.0.0"}},
		{"edge_106", &utls.HelloEdge_106, []string{"Chrome/106.0.0.0", "Edg/106.0.0.0"}},
		{"firefox_120", &utls.HelloFirefox_120, []string{"rv:120.0", "Firefox/120.0"}},
		{"safari_16", &utls.HelloSafari_16_0, []string{"Version/16.0", "Safari/605.1.15"}},
		{"ios_14", &utls.HelloIOS_14, []string{"iPhone OS 14_0", "Version/14.0"}},
		{"ios_legacy_111", &utls.HelloIOS_11_1, []string{"iPhone OS 11_1", "Version/11.1"}},
		{"android_okhttp", &utls.HelloAndroid_11_OkHttp, []string{"okhttp/"}},
		{"nil_falls_back", nil, []string{"Chrome/133.0.0.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := UserAgent(tc.id)
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("UserAgent(%v) = %q, missing %q", tc.id, got, want)
				}
			}
			if strings.Contains(got, "Go-http-client") {
				t.Errorf("UserAgent(%v) leaked the Go default UA: %q", tc.id, got)
			}
		})
	}
}

func TestHeadersCarryNoGoDefaultUA(t *testing.T) {
	h := Headers(nil)
	if ua := h.Get("User-Agent"); strings.Contains(ua, "Go-http-client") || ua == "" {
		t.Fatalf("default headers must carry a browser UA, got %q", ua)
	}
}

func TestHeadersFamilyConsistency(t *testing.T) {
	chrome := Headers(&utls.HelloChrome_133)
	if chrome.Get("User-Agent") == "" || chrome.Get("Accept") == "" || chrome.Get("Accept-Language") == "" {
		t.Fatal("chrome headers incomplete")
	}
	if !strings.Contains(chrome.Get("Sec-Ch-Ua"), `v="133"`) {
		t.Errorf("chrome Sec-CH-UA should carry the fingerprint version, got %q", chrome.Get("Sec-Ch-Ua"))
	}
	if chrome.Get("Sec-Ch-Ua-Mobile") != "?0" {
		t.Errorf("chrome Sec-CH-UA-Mobile = %q, want ?0 (desktop fingerprint)", chrome.Get("Sec-Ch-Ua-Mobile"))
	}

	// Firefox and Safari must not send Chromium client hints: doing so would
	// reintroduce exactly the cross-layer mismatch this package removes.
	for _, id := range []*utls.ClientHelloID{&utls.HelloFirefox_120, &utls.HelloSafari_16_0} {
		h := Headers(id)
		if h.Get("Sec-Ch-Ua") != "" {
			t.Errorf("%s headers must not carry Sec-CH-UA", id.Client)
		}
		if h.Get("User-Agent") == "" {
			t.Errorf("%s headers missing User-Agent", id.Client)
		}
	}
}

func TestApplyToDoesNotOverwriteExplicitHeaders(t *testing.T) {
	h := map[string][]string{"User-Agent": {"custom-agent"}}
	ApplyTo(h, &utls.HelloChrome_133)
	if got := h["User-Agent"][0]; got != "custom-agent" {
		t.Fatalf("explicit User-Agent overwritten: %q", got)
	}
	if h["Accept-Language"] == nil {
		t.Fatal("non-conflicting headers should still be added")
	}
}

func TestNoOriginOrReferer(t *testing.T) {
	// Servers validate Origin/Referer on some handshakes; injecting them
	// blindly would break connections, so the derived set must not contain them.
	h := Headers(&utls.HelloChrome_133)
	for _, k := range []string{"Origin", "Referer"} {
		if h.Get(k) != "" {
			t.Errorf("%s must not be derived automatically", k)
		}
	}
}
