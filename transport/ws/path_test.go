package ws

import "testing"

// Regression: the V2Ray share format carries the ws path as the "path"
// query param. NewWs used to read only u.Path, so such nodes dialed "/"
// and failed the upgrade against CDN-fronted servers (301/403 -> bare
// "websocket: bad handshake") while e.g. mihomo, which honors the param,
// connected fine.
func TestNewWsPathFromQueryParam(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&security=tls&type=ws&host=cf.example.com&path=%2Fcustompath&sni=cf.example.com#node"
	cfgI, _, err := NewWs(link)
	cfg, ok := cfgI.(*WsConfig)
	if !ok {
		t.Fatal("not a *WsConfig")
	}
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path != "/custompath" {
		t.Fatalf("Path = %q, want /custompath", cfg.Path)
	}
	if cfg.Hostname != "cf.example.com" {
		t.Fatalf("Hostname = %q", cfg.Hostname)
	}

	// URL-path form still wins and stays untouched.
	link2 := "vless://11111111-2222-3333-4444-555555555555@example.com:443/inlinepath?type=ws&path=%2Fignored#node2"
	cfg2I, _, err := NewWs(link2)
	cfg2, ok2 := cfg2I.(*WsConfig)
	if !ok2 {
		t.Fatal("not a *WsConfig")
	}
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Path != "/inlinepath" {
		t.Fatalf("Path = %q, want /inlinepath", cfg2.Path)
	}
}
