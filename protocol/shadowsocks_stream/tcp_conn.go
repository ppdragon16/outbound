package shadowsocks_stream

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

// TcpConn the struct that override the net.Conn methods
type TcpConn struct {
	net.Conn
	cipher *ciphers.StreamCipher

	init        bool
	writeBroken bool
	readMutex   sync.Mutex
	writeMutex  sync.Mutex
}

func NewTcpConn(c net.Conn, cipher *ciphers.StreamCipher) *TcpConn {
	return &TcpConn{
		Conn:   c,
		cipher: cipher,
	}
}

func (c *TcpConn) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if !c.cipher.DecryptInited() {
		ivLen := c.cipher.InfoIVLen()
		buf := b
		if len(buf) <= ivLen {
			buf = pool.GetBuffer(ivLen + len(b))
			defer pool.PutBuffer(buf)
		}
		n, err = io.ReadAtLeast(c.Conn, buf, ivLen)
		if err != nil {
			return 0, fmt.Errorf("invalid ivLen:%v, actual length:%v: %w", ivLen, n, err)
		}
		iv := buf[:ivLen]
		if err = c.cipher.InitDecrypt(iv); err != nil {
			return 0, err
		}

		if c.cipher.IV() == nil {
			// Copy: iv may alias the pooled scratch buffer or the caller's
			// slice, both of which get reused after Read returns.
			c.cipher.SetIV(append([]byte(nil), iv...))
		}
		if n == ivLen {
			// The first read may stop exactly at the IV boundary. Returning
			// (0, nil) here violates the io.Reader contract for non-empty
			// buffers (many callers treat it as EOF), so keep reading until
			// at least one payload byte arrives.
			m, rerr := io.ReadAtLeast(c.Conn, buf[n:], 1)
			n += m
			if rerr != nil {
				return 0, rerr
			}
		}
		n = copy(b, buf[ivLen:n])
		c.cipher.Decrypt(b[:n], b[:n])
	} else {
		n, err = c.Conn.Read(b)
		if err != nil {
			return n, err
		}
		c.cipher.Decrypt(b[:n], b[:n])
	}
	return n, nil
}

func (c *TcpConn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeBroken {
		return 0, net.ErrClosed
	}
	lenToWrite := len(b)
	ivLen := 0
	firstWrite := !c.init
	if !c.cipher.EncryptInited() {
		_, err = c.cipher.InitEncrypt()
		if err != nil {
			return 0, err
		}
	}
	if firstWrite {
		iv := c.cipher.IV()
		buf := pool.GetBuffer(len(b) + len(iv))
		defer pool.PutBuffer(buf)
		ivLen = len(iv)
		copy(buf, iv)
		copy(buf[ivLen:], b)
		b = buf

		// For SSR obfs.
		if innerConn, ok := c.Conn.(interface {
			SetCipher(cipher *ciphers.StreamCipher)
		}); ok {
			innerConn.SetCipher(c.cipher)
		}
		if innerConn, ok := c.Conn.(interface {
			SetAddrLen(addrLen int)
		}); ok {
			innerConn.SetAddrLen(lenToWrite)
		}
	}
	c.cipher.Encrypt(b[ivLen:], b[ivLen:])
	// On the first write the IV rides at the front of this frame, so the
	// stream stays uncommitted until every byte is out: a short write must
	// not let the next Write prepend a second IV.
	if _, err = iout.WriteFull(c.Conn, b); err != nil {
		c.writeBroken = true
		return 0, err
	}
	if firstWrite {
		c.init = true
	}
	return lenToWrite, nil
}

func (c *TcpConn) Cipher() *ciphers.StreamCipher {
	return c.cipher
}

// CloseWrite forwards the half-close to the inner conn so a relay FIN
// propagates through the tunnel as a transport FIN.
func (c *TcpConn) CloseWrite() error {
	if cw, ok := c.Conn.(netproxy.CloseWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}
