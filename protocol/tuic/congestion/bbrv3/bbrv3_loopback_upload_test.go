package bbrv3_test

// bbrv3_loopback_upload_test.go closes the gap the sampler's unit tests leave:
// they feed synthetic ack vectors and inspect the sampler's own bookkeeping, so
// no matter what they assert they never push a wide packet-number span through
// the real sending stack under a real RTT.
//
// This test drives the production upload path instead: a real quic-go
// connection on loopback through a one-way delay, with congestion.UseBBRV3
// installed on the live connection after OpenStreamSync -- exactly how the
// tuic/hysteria2 clients install it (protocol/tuic/congestion/utils.go) -- and
// a client that writes 24 MiB. The controller has to move all of it.
//
// The delay matters. Without it the loopback RTT is microseconds and the
// in-flight span stays tiny, so defects of the "sender quietly stops making
// progress" class (see koutbound e3ad962: its own sampler froze uploads past
// ~4096 packets at ~51 KB/s because a ring wrap-around read as a resend
// lockout) never show up. The verdict is a rolling progress gate rather than
// a bare deadline: the emulated path is not loss-free, so runs differ in
// absolute speed, but a sender parked at its floors advances nothing and
// trips the stall window however slow the rest of the run was.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol/tuic/congestion"
	"github.com/daeuniverse/quic-go"
	utls "github.com/refraction-networking/utls"
)

const (
	uploadBytes    = 24 << 20
	uploadChunk    = 32 << 10
	uploadDeadline = 45 * time.Second
	// stallWindow is the rolling window over which the upload must advance at
	// least minWindowProgress; a controller parked at its floors advances
	// nothing and trips this long before the overall deadline.
	stallWindow       = 8 * time.Second
	minWindowProgress = 1 << 20 // 1 MiB per 8s ≈ 1 Mbps, far below any healthy rate
	// oneWayDelay is the client->server leg delay of the emulated path, so the
	// path RTT is about twice this.
	oneWayDelay = 50 * time.Millisecond
	// maxPayloadPerPacket is a deliberately loose upper bound on the stream
	// data one packet can carry, used only to turn the upload volume into a
	// lower bound on the packet-number span. The MTU this fork ships is 1280
	// bytes, so the real span is higher than uploadBytes/maxPayloadPerPacket.
	maxPayloadPerPacket = 1400
	// minSpan is the packet-number span the upload must exceed for this test
	// to be meaningful: wide enough to slide past any bounded sampler window
	// of the classic ~4k-entry class.
	minSpan = 16 << 10
)

// TestBBRV3LoopbackUploadCompletes requires a wide-span upload across a real
// RTT to finish inside the deadline. A frozen or lockout-prone controller
// stalls far short of the volume; a healthy one completes in seconds.
func TestBBRV3LoopbackUploadCompletes(t *testing.T) {
	if packets := uploadBytes / maxPayloadPerPacket; packets < minSpan {
		t.Fatalf("uploadBytes=%d carries only %d packets, below the %d-packet span this test exists to exercise",
			uploadBytes, packets, minSpan)
	}

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("net.ListenUDP() error = %v", err)
	}
	defer serverConn.Close()
	_ = serverConn.SetReadBuffer(8 << 20)
	_ = serverConn.SetWriteBuffer(8 << 20)
	listener, err := quic.Listen(serverConn, serverTLSConfig(), &quic.Config{})
	if err != nil {
		t.Fatalf("quic.Listen() error = %v", err)
	}
	defer listener.Close()

	// The client dials the relay instead of the server, so its datagrams reach
	// the server one way delay later. A relay rather than a net.PacketConn
	// wrapper, because quic-go's transport stops its listen loop via the read
	// deadline and a wrapper that polls would swallow that signal.
	relayAddr, closeRelay := startDelayRelay(t, listener.Addr(), oneWayDelay)
	defer closeRelay()

	var received atomic.Int64
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.CloseWithError(0, "done")
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		buf := make([]byte, 256<<10)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				received.Add(int64(n))
			}
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				serverDone <- err
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), uploadDeadline)
	defer cancel()
	conn, err := quic.DialAddr(ctx, relayAddr.String(), clientTLSConfig(), &quic.Config{})
	if err != nil {
		t.Fatalf("quic.DialAddr() error = %v", err)
	}
	defer conn.CloseWithError(0, "done")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync() error = %v", err)
	}
	// The QUIC-based clients install the controller on the live connection
	// after the stream is open (protocol/tuic/congestion/utils.go), not
	// through the dial config.
	congestion.UseBBRV3(conn)

	payload := make([]byte, uploadChunk)
	for i := range payload {
		payload[i] = byte(i)
	}
	// The stream write blocks on an internal channel the dial context does not
	// unblock, so a controller that stops granting window parks the caller for
	// ever. Bound the transfer from the outside, the way a relay's own
	// teardown does.
	var written atomic.Int64
	writeDone := make(chan error, 1)
	uploadDone := make(chan struct{})
	start := time.Now()
	go func() {
		for written.Load() < uploadBytes {
			n, err := stream.Write(payload)
			written.Add(int64(n))
			if err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- stream.Close()
		close(uploadDone)
	}()

	// Two gates, because the emulated path is not loss-free: a stalled
	// sender is NO progress, not slow progress.
	//
	// Gate 1 (the real one): a rolling progress window. The defect class this
	// test exists for -- a sampler that stops registering sends and parks the
	// controller at its floors -- shows up as bytes written flat-lining. Any
	// stallWindow without at least minWindowProgress bytes is a failure,
	// however much was moved before it.
	// Gate 2: the overall deadline bounds the test's run time.
	startSample, startSampleAt := written.Load(), time.Now()
	monitorDone := make(chan error, 1)
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				now, nowAt := written.Load(), time.Now()
				if now >= uploadBytes {
					monitorDone <- nil
					return
				}
				if now == startSample && nowAt.Sub(startSampleAt) >= stallWindow {
					_ = conn.CloseWithError(0, "stalled")
					monitorDone <- fmt.Errorf("sender stopped making progress: %d of %d bytes (%.1f MiB) moved, then nothing for %v",
						now, uploadBytes, float64(now)/(1<<20), stallWindow)
					return
				}
				if now-startSample >= minWindowProgress {
					startSample, startSampleAt = now, nowAt
				}
			case <-uploadDone:
				monitorDone <- nil
				return
			}
		}
	}()

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("upload write failed after %d of %d bytes: %v", written.Load(), uploadBytes, err)
		}
	case err := <-monitorDone:
		if err != nil {
			t.Fatalf("upload stalled: %v", err)
		}
	case <-time.After(uploadDeadline):
		_ = conn.CloseWithError(0, "stalled")
		t.Fatalf("upload stalled: congestion.UseBBRV3 moved %d of %d bytes (%.1f MiB) in %v and never finished",
			written.Load(), uploadBytes, float64(written.Load())/(1<<20), uploadDeadline)
	}

	// Written is not delivered: wait for the server to drain the stream.
	drainDeadline := time.Now().Add(uploadDeadline)
	for received.Load() < uploadBytes && time.Now().Before(drainDeadline) {
		select {
		case err := <-serverDone:
			if err != nil {
				t.Fatalf("server stream error = %v", err)
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	if got := received.Load(); got < uploadBytes {
		t.Fatalf("server received %d of %d bytes: the upload did not complete", got, uploadBytes)
	}

	elapsed := time.Since(start)
	t.Logf("moved %d bytes in %v (%.1f MiB/s) across at least %d packet numbers",
		uploadBytes, elapsed.Round(time.Millisecond),
		float64(uploadBytes)/(1<<20)/elapsed.Seconds(),
		uploadBytes/maxPayloadPerPacket)
}

// startDelayRelay listens on a UDP socket the client can dial instead of the
// server, forwarding client datagrams to serverAddr one delay later and server
// datagrams straight back.
//
// The delay is injected by a single writer goroutine draining a timestamped
// queue, NOT by one time.AfterFunc per datagram: a timer per packet makes
// thousands of concurrent timer goroutines issue write syscalls, the reader
// goroutine starves, and the relay's kernel receive queue -- clamped by
// net.core.rmem_max well below what the emulated in-flight volume needs --
// turns quic-go bursts into chronic silent loss. That loss reads as sustained
// path loss and pins any congestion controller to a crawl (measured: CUBIC
// 3.8 MiB of 24 MiB in 30 s on the timer-per-packet design; the same path
// through the queue below is loss-free).
func startDelayRelay(t *testing.T, serverAddr net.Addr, delay time.Duration) (net.Addr, func()) {
	t.Helper()
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("net.ListenUDP() error = %v", err)
	}

	type scheduled struct {
		data []byte
		to   net.Addr
		at   time.Time
	}
	// The queue holds at most one in-flight window's worth of datagrams; the
	// writer keeps the socket queues shallow by draining at the scheduled
	// times.
	queue := make(chan scheduled, 1<<16)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for d := range queue {
			if wait := time.Until(d.at); wait > 0 {
				time.Sleep(wait)
			}
			if _, err := relay.WriteTo(d.data, d.to); err != nil {
				return
			}
		}
	}()

	go func() {
		defer close(queue)
		buf := make([]byte, 65536)
		var clientAddr net.Addr
		for {
			n, from, err := relay.ReadFrom(buf)
			if err != nil {
				// The socket was closed; stop relaying.
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			if from.String() == serverAddr.String() {
				if clientAddr != nil {
					queue <- scheduled{data: data, to: clientAddr, at: time.Now()}
				}
				continue
			}
			clientAddr = from
			queue <- scheduled{data: data, to: serverAddr, at: time.Now().Add(delay)}
		}
	}()

	return relay.LocalAddr(), func() {
		_ = relay.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
}

func serverTLSConfig() *utls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "loopback"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return &utls.Config{
		Certificates: []utls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"bbrv3-sampler-test"},
		MinVersion:   utls.VersionTLS13,
	}
}

func clientTLSConfig() *utls.Config {
	return &utls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"bbrv3-sampler-test"},
		MinVersion:         utls.VersionTLS13,
	}
}
