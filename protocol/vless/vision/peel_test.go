package vision

import (
	"net"
	"testing"

	"github.com/daeuniverse/outbound/pkg/coalesce"
	utls "github.com/refraction-networking/utls"
)

// Two wrapper levels are the point: the peel must walk all of them.

// wrappingConn mimics protocol/vless.Conn: a wrapper that peels to its child.
type wrappingConn struct {
	net.Conn
}

func (w *wrappingConn) IntrinsicConn() net.Conn { return w.Conn }

// Regression: the peel used to stop after ONE level, so a chain like
// vless.Conn -> wrapper -> wrapper -> *utls.Conn failed with
// "XTLS only supports TLS and REALITY directly for now: <wrapper>".
// The peel must walk every wrapper down to the terminal TLS conn.
func TestNewConnUnwrapsNestedWrappers(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	co := coalesce.New(c1)
	utlsConn := utls.Client(co, &utls.Config{ServerName: "example.com"})

	var conn net.Conn = &wrappingConn{Conn: &wrappingConn{Conn: utlsConn}}

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
