package socks5

import (
	"net"
	"strings"
	"testing"
	"time"
)

// stubSocks5Server performs the greeting + password-auth exchange and then
// echoes the request's first byte back, enough for connect() to complete.
func stubSocks5Server(t *testing.T, wantAuth bool) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("listen:", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		hdr := make([]byte, 2)
		if _, err := io_ReadFull(c, hdr); err != nil {
			return
		}
		// Consume the full method list advertised in the greeting.
		if _, err := io_ReadFull(c, make([]byte, hdr[1])); err != nil {
			return
		}
		if wantAuth {
			// Choose password auth, then accept any credentials and reply OK.
			if _, err := c.Write([]byte{5, 2}); err != nil {
				return
			}
			ver := make([]byte, 1)
			ulen := make([]byte, 1)
			if _, err := io_ReadFull(c, ver); err != nil {
				return
			}
			if _, err := io_ReadFull(c, ulen); err != nil {
				return
			}
			if _, err := io_ReadFull(c, make([]byte, ulen[0])); err != nil {
				return
			}
			plen := make([]byte, 1)
			if _, err := io_ReadFull(c, plen); err != nil {
				return
			}
			if _, err := io_ReadFull(c, make([]byte, plen[0])); err != nil {
				return
			}
			if _, err := c.Write([]byte{1, 0}); err != nil {
				return
			}
		} else if _, err := c.Write([]byte{5, 0}); err != nil {
			return
		}
		// Request: VER CMD RSV ATYP ADDR PORT — read and echo VER+CMD.
		req := make([]byte, 6)
		if _, err := io_ReadFull(c, req); err != nil {
			return
		}
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skip("dial stub:", err)
	}
	return c
}

func io_ReadFull(c net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		k, err := c.Read(buf[n:])
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func TestSocks5CredentialValidation(t *testing.T) {
	t.Run("password only rejected", func(t *testing.T) {
		s := &Socks5{addr: "127.0.0.1:1", password: "pw"}
		c := stubSocks5Server(t, true)
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, err := s.connect(c, "example.com:80", 1, nil)
		if err == nil || !strings.Contains(err.Error(), "1 to 255 bytes") {
			t.Fatalf("want credential error, got %v", err)
		}
	})
	t.Run("oversized password rejected", func(t *testing.T) {
		s := &Socks5{addr: "127.0.0.1:1", user: "u", password: strings.Repeat("x", 256)}
		c := stubSocks5Server(t, true)
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, err := s.connect(c, "example.com:80", 1, nil)
		if err == nil || !strings.Contains(err.Error(), "1 to 255 bytes") {
			t.Fatalf("want credential error, got %v", err)
		}
	})
	t.Run("paired credentials proceed", func(t *testing.T) {
		s := &Socks5{addr: "127.0.0.1:1", user: "u", password: "p"}
		c := stubSocks5Server(t, true)
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := s.connect(c, "example.com:80", 1, nil); err != nil {
			t.Fatalf("paired credentials must proceed: %v", err)
		}
	})
	t.Run("anonymous proceeds", func(t *testing.T) {
		s := &Socks5{addr: "127.0.0.1:1"}
		c := stubSocks5Server(t, false)
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := s.connect(c, "example.com:80", 1, nil); err != nil {
			t.Fatalf("anonymous must proceed: %v", err)
		}
	})
}
