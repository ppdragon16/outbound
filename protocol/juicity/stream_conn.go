package juicity

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/quic-go"
)

type Conn struct {
	quic.Stream
	Metadata *Metadata

	writeMutex sync.Mutex
	onceWrite  bool
	onceRead   sync.Once

	closeDeferFn func()

	closeOnce sync.Once
	closeErr  error

	localAddr  net.Addr
	remoteAddr net.Addr
}

// reqHeader builds the request header into a small pooled buffer. The payload
// is written separately via net.Buffers so a large payload cannot inflate this
// buffer past the pool's largest bucket (same cliff as vless/anytls).
func (c *Conn) reqHeader() (buf []byte) {
	addrLen := c.Metadata.Len()
	buf = pool.GetBuffer(1 + addrLen)
	buf[0] = NetworkToByte(c.Metadata.Network)
	c.Metadata.PackTo(buf[1:])
	return buf
}

func (c *Conn) readReqHeader() (err error) {
	buf := pool.GetBuffer(1)
	defer pool.PutBuffer(buf)
	if _, err = io.ReadFull(c.Stream, buf[:1]); err != nil {
		return err
	}
	c.Metadata.Network = ParseNetwork(buf[0])
	n := c.Metadata.Len()
	if n < 2 {
		return fmt.Errorf("invalid juicity header")
	}
	if _, err = c.Metadata.Unpack(c.Stream); err != nil {
		return err
	}
	return nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if !c.onceWrite {
		if c.Metadata.IsClient {
			header := c.reqHeader()
			defer pool.PutBuffer(header)
			buffers := net.Buffers{header}
			if len(b) > 0 {
				buffers = append(buffers, b)
			}
			if _, err = buffers.WriteTo(c.Stream); err != nil {
				return 0, fmt.Errorf("write header: %w", err)
			}
			c.onceWrite = true
			return len(b), nil
		}
	}
	return c.Stream.Write(b)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	c.onceRead.Do(func() {
		if !c.Metadata.IsClient {
			if err = c.readReqHeader(); err != nil {
				return
			}
		}
	})
	return c.Stream.Read(b)
}

// LocalAddr implements net.Conn.
func (c *Conn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr implements net.Conn.
func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.close()
	})
	return c.closeErr
}

func (c *Conn) CloseWrite() error {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	// As documented by the quic-go library, this doesn't actually close the entire stream.
	// It prevents further writes, which in turn will result in an EOF signal being sent the other side of stream when
	// reading.
	// We can still read from this stream.
	return c.Stream.Close()
}

func (c *Conn) close() error {
	if c.closeDeferFn != nil {
		defer c.closeDeferFn()
	}

	// https://github.com/cloudflare/cloudflared/commit/ed2bac026db46b239699ac5ce4fcf122d7cab2cd
	// Make sure a possible writer does not block the lock forever. We need it, so we can close the writer
	// side of the stream safely.
	_ = c.Stream.SetWriteDeadline(time.Now())

	// This lock is eventually acquired despite Write also acquiring it, because we set a deadline to writes.
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	// We have to clean up the receiving stream ourselves since the Close in the bottom does not handle that.
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}

var _ net.Conn = &Conn{}

func NewConn(stream quic.Stream, mdata *Metadata, closeDeferFn func(), localAddr, remoteAddr net.Addr) *Conn {
	if mdata == nil {
		mdata = &Metadata{}
	}
	return &Conn{
		Stream:       stream,
		Metadata:     mdata,
		closeDeferFn: closeDeferFn,
		localAddr:    localAddr,
		remoteAddr:   remoteAddr,
	}
}
