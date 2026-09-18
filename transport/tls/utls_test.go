package tls

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

// Share links carry the fingerprint as "fp". Xray and sing-box resolve that
// name case-insensitively and accept "android", so links that work with those
// clients must resolve here too.
func TestNameToUTLSClientHelloIDNormalizesNames(t *testing.T) {
	for _, name := range []string{"chrome", "Chrome", " CHROME ", "ChRoMe"} {
		got, err := nameToUtlsClientHelloID(name)
		if err != nil {
			t.Fatalf("resolve %q: %v", name, err)
		}
		if got != &utls.HelloChrome_Auto {
			t.Fatalf("resolve %q: got %#v, want %#v", name, got, &utls.HelloChrome_Auto)
		}
	}
	got, err := nameToUtlsClientHelloID("Android")
	if err != nil {
		t.Fatalf("resolve android alias: %v", err)
	}
	if got != &utls.HelloAndroid_11_OkHttp {
		t.Fatalf("android alias resolved to %#v, want %#v", got, &utls.HelloAndroid_11_OkHttp)
	}
	if _, err := nameToUtlsClientHelloID("no_such_fingerprint"); err == nil {
		t.Fatal("expected an error for an unknown fingerprint")
	}
}
