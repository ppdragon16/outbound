package coalesce

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Regression: without FlushConn.IntrinsicConn, XTLS/Vision's wrapper peel
// (interface{ IntrinsicConn() net.Conn }) stops at *FlushConn and every
// vless vision node fails its connectivity check with
// "XTLS only supports TLS and REALITY directly for now: *coalesce.FlushConn".
func TestFlushConnIntrinsicConnPeelsTLSLayer(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	co := New(c1)
	tlsConn := utls.Client(co, &utls.Config{ServerName: "example.com"})
	f := NewFlushConn(tlsConn, co)

	// The peel must go through in one step, exactly as vision does it.
	iconn, ok := interface{}(f).(interface{ IntrinsicConn() net.Conn })
	if !ok {
		t.Fatal("FlushConn does not implement IntrinsicConn()")
	}
	if _, ok := iconn.IntrinsicConn().(*utls.Conn); !ok {
		t.Fatalf("IntrinsicConn() = %T, want *utls.Conn", iconn.IntrinsicConn())
	}

	// A non-TLS inner conn (no IntrinsicConn of its own) is returned as-is.
	inner := &net.TCPConn{}
	f2 := NewFlushConn(inner, co)
	if got := f2.IntrinsicConn(); got != net.Conn(inner) {
		t.Fatalf("IntrinsicConn() = %T, want the inner conn itself", got)
	}
	_ = time.Second
	_ = tls.VersionTLS13
}
