package v2ray

import (
	"encoding/json"
	"testing"
)

func TestFlexibleBool(t *testing.T) {
	cases := map[string]bool{
		`true`:    true,
		`false`:   false,
		`1`:       true,
		`0`:       false,
		`"true"`:  true,
		`"false"`: false,
		`"1"`:     true,
		`"0"`:     false,
		`""`:      false,
		`null`:    false,
		`2.5`:     true,
	}
	for in, want := range cases {
		var b FlexibleBool
		if err := json.Unmarshal([]byte(in), &b); err != nil {
			t.Fatalf("unmarshal %q: %v", in, err)
		}
		if bool(b) != want {
			t.Fatalf("FlexibleBool(%q) = %v, want %v", in, bool(b), want)
		}
	}
}

func TestFlexibleInt(t *testing.T) {
	cases := map[string]int{
		`8`:     8,
		`"8"`:   8,
		`8.9`:   8,
		`"8.9"`: 8,
		`true`:  1,
		`false`: 0,
		`null`:  0,
		`""`:    0,
	}
	for in, want := range cases {
		var i FlexibleInt
		if err := json.Unmarshal([]byte(in), &i); err != nil {
			t.Fatalf("unmarshal %q: %v", in, err)
		}
		if int(i) != want {
			t.Fatalf("FlexibleInt(%q) = %d, want %d", in, int(i), want)
		}
	}
}

func TestV2RayLenientUnmarshal(t *testing.T) {
	// A vmess JSON with loosely-typed bool/int/string fields.
	raw := []byte(`{"v":"2","ps":"x","add":"1.2.3.4","port":443,"id":"u","aid":"0","net":"tcp","type":"none","tls":"","allowInsecure":"true","mux":1,"muxConcurrency":"8"}`)
	var v V2Ray
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v.Port != "443" {
		t.Fatalf("Port = %q, want %q", v.Port, "443")
	}
	if !bool(v.AllowInsecure) {
		t.Fatal("AllowInsecure should be true")
	}
	if !bool(v.Mux) {
		t.Fatal("Mux should be true")
	}
	if int(v.MuxConcurrency) != 8 {
		t.Fatalf("MuxConcurrency = %d, want 8", int(v.MuxConcurrency))
	}
}
