// Package vision implements VLESS flow `xtls-rprx-vision` introduced by Xray-core.
package vision

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"reflect"
	"unsafe"

	xtls "crypto/tls"

	"github.com/daeuniverse/outbound/transport/tls"
	utls "github.com/refraction-networking/utls"
)

var ErrNotTLS13 = errors.New("XTLS Vision based on TLS 1.3 outer connection")

func NewPacketConn(conn net.Conn, userUUID []byte, network string, addr string) (*PacketConn, error) {
	c, err := NewConn(conn, userUUID)
	if err != nil {
		return nil, err
	}
	return &PacketConn{c, network, addr}, nil
}

func NewConn(conn net.Conn, userUUID []byte) (*Conn, error) {
	c := &Conn{
		overlayConn:                conn,
		userUUID:                   userUUID,
		packetsToFilter:            6,
		needHandshake:              true,
		readFilterUUID:             true,
		writeFilterApplicationData: true,
	}
	c.writer = &writeWrapper{
		vision: c,
	}
	c.reader = &readWrapper{
		vision: c,
	}
	// Unwrap intermediate wrappers (vless.Conn, fragment conns, ...) until we
	// reach the actual TLS/REALITY connection. Each wrapper exposes IntrinsicConn() returning its child;
	// the TLS types are terminal leaves and do not implement it. The walk is
	// bounded so a misbehaving wrapper cannot hang the dial path.
	ic := conn
	for i := 0; ; i++ {
		iconn, ok := ic.(interface{ IntrinsicConn() net.Conn })
		if !ok {
			break
		}
		if i >= 16 {
			return nil, fmt.Errorf("XTLS intrinsic conn unwrap exceeded depth limit: %T", ic)
		}
		ic = iconn.IntrinsicConn()
	}
	// visionBuffers is implemented by the utls fork: it hands out the actual
	// *bytes.Reader and pooled BytesBuffer, so Vision never has to reproduce
	// the struct layout with unsafe offsets. Those offsets silently broke once
	// rawInput became an interface: casting an interface's address to
	// *bytes.Buffer reads its header as buffer fields and desynchronizes the
	// direct-copy handoff (large transfers corrupted after the first record).
	type visionBuffers interface {
		VisionReadBuffers() (*bytes.Reader, utls.BytesBuffer)
	}
	useBuffers := func(conn any) bool {
		vb, ok := conn.(visionBuffers)
		if !ok {
			return false
		}
		input, raw := vb.VisionReadBuffers()
		c.input = input
		if raw != nil {
			c.rawInput = raw
		}
		return true
	}
	var t reflect.Type
	var p unsafe.Pointer
	typed := false
	if tlsConn, ok := ic.(*utls.Conn); ok {
		c.Conn = tlsConn.NetConn()
		c.tlsConn = tlsConn
		typed = useBuffers(tlsConn)
		t = reflect.TypeOf(tlsConn).Elem()
		p = unsafe.Pointer(tlsConn)
	} else if tlsConn, ok := ic.(*xtls.Conn); ok {
		c.Conn = tlsConn.NetConn()
		c.tlsConn = tlsConn
		t = reflect.TypeOf(tlsConn).Elem()
		p = unsafe.Pointer(tlsConn)
	} else if utlsConn, ok := ic.(*utls.UConn); ok {
		c.Conn = utlsConn.NetConn()
		c.tlsConn = utlsConn
		typed = useBuffers(utlsConn.Conn)
		t = reflect.TypeOf(utlsConn.Conn).Elem()
		p = unsafe.Pointer(utlsConn.Conn)
	} else if realityConn, ok := ic.(*tls.RealityUConn); ok {
		// logrus.Infoln("realityConn")
		c.Conn = realityConn.NetConn()
		c.tlsConn = realityConn.UConn
		typed = useBuffers(realityConn.Conn)
		t = reflect.TypeOf(realityConn.Conn).Elem()
		p = unsafe.Pointer(realityConn.Conn)
	} else {
		return nil, fmt.Errorf("XTLS only supports TLS and REALITY directly for now: %T", ic)
	}
	if typed {
		return c, nil
	}
	// Fallback for TLS implementations without VisionReadBuffers
	// (crypto/tls always lands here, and so do utls builds that predate the
	// accessor). The offset-based access is only correct while rawInput is a
	// *bytes.Buffer: a pooled utls fork types it as an interface, and casting
	// an interface's address to *bytes.Buffer reinterprets its header as
	// buffer fields, silently desynchronizing the direct-copy handoff and
	// corrupting every transfer past the first TLS record. Refuse that shape
	// loudly instead of degrading into corrupt streams.
	i, _ := t.FieldByName("input")
	r, _ := t.FieldByName("rawInput")
	// When the TLS implementation's buffers cannot be reached safely, keep
	// the connection but mark the direct transition as unavailable: the peer
	// chooses direct on its own, so the handshake and framed relay still work
	// and only the handoff itself must fail loudly instead of corrupting the
	// stream.
	if i.Name == "" || r.Name == "" {
		c.readBuffersUnsafe = true
		return c, nil
	}
	if r.Type.Kind() == reflect.Interface {
		// A pooled utls fork types rawInput as an interface and is expected to
		// provide VisionReadBuffers; without it the offset cast would
		// reinterpret the interface header as buffer fields.
		c.readBuffersUnsafe = true
		return c, nil
	}
	// These are stdlib/utls internals, not API: verify their exact shapes
	// before touching them. crypto/tls has carried both as value fields for
	// years, but a future Go release may change that (input was a
	// *bytes.Reader in older releases), and a silent layout mismatch here
	// desynchronizes the direct-copy handoff instead of failing.
	if i.Type != reflect.TypeOf(bytes.Reader{}) || r.Type != reflect.TypeOf(bytes.Buffer{}) {
		c.readBuffersUnsafe = true
		return c, nil
	}
	c.input = (*bytes.Reader)(unsafe.Add(p, i.Offset))
	if raw := (*bytes.Buffer)(unsafe.Add(p, r.Offset)); raw != nil {
		c.rawInput = raw
	}
	return c, nil
}
