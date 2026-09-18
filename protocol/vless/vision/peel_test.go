package vision

import (
	"net"
	"testing"

	"github.com/daeuniverse/outbound/pkg/coalesce"
	utls "github.com/refraction-networking/utls"
)

// wrappingConn mimics protocol/vless.Conn: a wrapper that peels to its child.
type wrappingConn struct {
	net.Conn
}

func (w *wrappingConn) IntrinsicConn() net.Conn { return w.Conn }

// Regression: the peel used to stop after ONE level, so
// vless.Conn -> *coalesce.FlushConn -> *utls.Conn failed with
// "XTLS only supports TLS and REALITY directly for now: *coalesce.FlushConn".
// The peel must walk wrappers down to the terminal TLS conn.
func TestNewConnUnwrapsNestedWrappers(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	co := coalesce.New(c1)
	utlsConn := utls.Client(co, &utls.Config{ServerName: "example.com"})

	var conn net.Conn = &wrappingConn{Conn: coalesce.NewFlushConn(utlsConn, co)}

	c, err := NewConn(conn, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	if _, ok := c.tlsConn.(*utls.Conn); !ok {
		t.Fatalf("tlsConn = %T, want *utls.Conn", c.tlsConn)
	}
	if c.Conn != net.Conn(co) {
		t.Fatalf("c.Conn = %T, want the coalescer conn", c.Conn)
	}
}
