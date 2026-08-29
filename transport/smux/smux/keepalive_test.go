package smux

import (
	"net"
	"testing"
	"time"
)

// newSessionPair builds a client/server session pair over net.Pipe. Server
// keepalive is disabled entirely, mirroring a sing-box peer that sends nothing
// on an idle session: every frame the client receives must come from real
// stream data.
func newSessionPair(t *testing.T, clientCfg *Config) (*Session, *Session) {
	t.Helper()
	c1, c2 := net.Pipe()
	srvCfg := *DefaultConfig
	srvCfg.KeepAliveDisabled = true
	srv, err := Server(c2, &srvCfg)
	if err != nil {
		t.Fatalf("Server: %v", err)
	}
	cli, err := Client(c1, clientCfg)
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	t.Cleanup(func() {
		cli.Close()
		srv.Close()
	})
	return cli, srv
}

func TestVerifyConfigKeepAliveTimeoutZero(t *testing.T) {
	cfg := *DefaultConfig
	cfg.KeepAliveInterval = 10 * time.Millisecond
	cfg.KeepAliveTimeout = 0
	if err := VerifyConfig(&cfg); err != nil {
		t.Fatalf("VerifyConfig with KeepAliveTimeout=0 = %v, want nil", err)
	}
	cfg.KeepAliveTimeout = cfg.KeepAliveInterval / 2
	if err := VerifyConfig(&cfg); err == nil {
		t.Fatal("VerifyConfig with KeepAliveTimeout < KeepAliveInterval = nil, want error")
	}
}

// TestKeepAliveTimeoutZeroKeepsSilentIdleSession is the regression test for the
// production churn: with the old default config (KeepAliveTimeout=30s) an idle
// session that receives no frames was closed by keepalive, and the smux pool's
// pre-warm replenish re-dialed it in a loop. Timeout=0 must keep the session
// alive even though the peer never sends anything.
func TestKeepAliveTimeoutZeroKeepsSilentIdleSession(t *testing.T) {
	cfg := *DefaultConfig
	cfg.KeepAliveInterval = 20 * time.Millisecond
	cfg.KeepAliveTimeout = 0
	cli, _ := newSessionPair(t, &cfg)

	// Many ping intervals pass; the server side stays completely silent.
	time.Sleep(300 * time.Millisecond)
	if cli.IsClosed() {
		t.Fatal("silent idle session was closed despite KeepAliveTimeout=0")
	}
}

// TestKeepAliveTimeoutKillsSilentIdleSession is the control group: the same
// silent peer, but with a positive KeepAliveTimeout the idle-kill must still
// work (dead-link detection remains available to callers who want it).
func TestKeepAliveTimeoutKillsSilentIdleSession(t *testing.T) {
	cfg := *DefaultConfig
	cfg.KeepAliveInterval = 20 * time.Millisecond
	cfg.KeepAliveTimeout = 60 * time.Millisecond
	cli, _ := newSessionPair(t, &cfg)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cli.IsClosed() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("silent idle session was not closed with KeepAliveTimeout>0")
}
