package client

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/quic-go"
)

// stalledDatagramConn reports a stalled datagram send queue (the queue stayed
// full with nothing packed for its whole timeout) and blocks in CloseWithError,
// the way a real connection does while its send queue waits for a socket write
// that is not draining.
type stalledDatagramConn struct {
	quic.Connection
	closes  atomic.Int32
	closing chan struct{}
	release chan struct{}
}

func (c *stalledDatagramConn) SendDatagram([]byte) error {
	return quic.ErrDatagramQueueFullTimeout
}

func (c *stalledDatagramConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	c.closes.Add(1)
	select {
	case c.closing <- struct{}{}:
	default:
	}
	<-c.release
	return nil
}

// TestStalledDatagramQueueRetiresWithoutBlockingTheWriter pins that a write
// which hits the datagram send queue timeout returns immediately: the retire
// must not run on the writer's goroutine, because the writer has just waited out
// the queue timeout and CloseWithError waits for the connection's run loop
// (which waits for a socket write that may itself be stuck). It also pins that
// concurrent timed-out writes retire the connection exactly once.
func TestStalledDatagramQueueRetiresWithoutBlockingTheWriter(t *testing.T) {
	conn := &stalledDatagramConn{closing: make(chan struct{}, 4), release: make(chan struct{})}
	defer close(conn.release) // unblock the retire goroutine on the way out
	u := &udpConn{conn: conn, sm: &udpSessionManager{}}
	msg := protocol.UDPMessage{
		SessionID: 1,
		FragCount: 1,
		AddrPort:  netip.MustParseAddrPort("1.1.1.1:53"),
		Data:      []byte("probe"),
	}
	buf := pool.GetBuffer(protocol.MaxUDPSize)
	defer pool.PutBuffer(buf)

	for i := 0; i < 3; i++ {
		done := make(chan error, 1)
		go func() { done <- u.WritePacket(buf, msg) }()
		select {
		case err := <-done:
			if !errors.Is(err, quic.ErrDatagramQueueFullTimeout) {
				t.Fatalf("write %d error = %v, want ErrDatagramQueueFullTimeout", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("WritePacket blocked on the retire")
		}
	}

	select {
	case <-conn.closing:
	case <-time.After(time.Second):
		t.Fatal("the stalled connection was never retired")
	}
	time.Sleep(50 * time.Millisecond)
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("CloseWithError called %d times, want 1", got)
	}
}
