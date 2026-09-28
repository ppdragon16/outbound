package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// byteCounter accumulates transferred bytes across streams.
type byteCounter struct{ n atomic.Int64 }

func (c *byteCounter) Add(n int) { c.n.Add(int64(n)) }
func (c *byteCounter) Load() int64 {
	return c.n.Load()
}

// bodySize is the request body the upload measurement pushes. It only needs to
// be larger than what can be transferred within the measurement window.
const bodySize = 200_000_000

// transfer streams the target's data (or pushes data for -up) until deadline.
func transfer(d *clientDialer, target, path string, up bool, deadline time.Time, counter *byteCounter) error {
	ctx, cancel := context.WithTimeout(context.Background(), deadline.Sub(time.Now())+10*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	method, body := "GET", ""
	if up {
		method = fmt.Sprintf("POST")
		body = fmt.Sprintf("Content-Length: %d\r\n", bodySize)
	}
	hdr := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n\r\n", method, path, host, body)
	if _, err := conn.Write([]byte(hdr)); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	// For a download, validate the response before reading the body: rate
	// limits and errors would otherwise look exactly like a dead relay. For
	// an upload the response only arrives after the body, so it is checked
	// after the send loop instead.
	br := bufio.NewReaderSize(conn, 64<<10)
	if !up {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		status, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read status: %w", err)
		}
		if !strings.Contains(status, " 2") {
			return fmt.Errorf("target returned %q", strings.TrimSpace(status))
		}
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return fmt.Errorf("read headers: %w", err)
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
	}

	buf := make([]byte, 64<<10)
	if up {
		for time.Now().Before(deadline) {
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Write(buf)
			counter.Add(n)
			if err != nil {
				return nil
			}
		}
		// The target answers after the body; report a non-2xx as an error.
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		status, err := br.ReadString('\n')
		if err == nil && !strings.Contains(status, " 2") {
			return fmt.Errorf("target returned %q", strings.TrimSpace(status))
		}
		return nil
	}
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := br.Read(buf)
		counter.Add(n)
		if err != nil {
			return nil
		}
	}
	return nil
}
