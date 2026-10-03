package direct

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNSMode is how the stub resolver answers a query.
type fakeDNSMode int

const (
	// fakeDNSAnswer returns 4.4.4.4 / 2001:db8::4.
	fakeDNSAnswer fakeDNSMode = iota
	// fakeDNSBlackhole reads queries and never answers, like a dropped route.
	fakeDNSBlackhole
	// fakeDNSEmpty answers successfully without any record.
	fakeDNSEmpty
)

// fakeDNS is a stub DNS server on a loopback UDP socket.
type fakeDNS struct {
	addr string
	pc   net.PacketConn
	mode fakeDNSMode
}

func newFakeDNS(t *testing.T, mode fakeDNSMode) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stub DNS: %v", err)
	}
	s := &fakeDNS{addr: pc.LocalAddr().String(), pc: pc, mode: mode}
	t.Cleanup(func() { _ = pc.Close() })
	go s.serve()
	return s
}

func (s *fakeDNS) serve() {
	buf := make([]byte, 1500)
	for {
		n, addr, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if s.mode == fakeDNSBlackhole {
			continue
		}
		var parser dnsmessage.Parser
		hdr, err := parser.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := parser.Question()
		if err != nil {
			continue
		}

		reply := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:                 hdr.ID,
				Response:           true,
				RecursionDesired:   true,
				RecursionAvailable: true,
			},
			Questions: []dnsmessage.Question{q},
		}
		if s.mode != fakeDNSEmpty {
			switch q.Type {
			case dnsmessage.TypeA:
				reply.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AResource{A: [4]byte{4, 4, 4, 4}},
				}}
			case dnsmessage.TypeAAAA:
				reply.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}},
				}}
			}
		}
		packed, err := reply.Pack()
		if err != nil {
			continue
		}
		_, _ = s.pc.WriteTo(packed, addr)
	}
}

// resolverTo builds the Go resolver whose queries go to the stub server.
func resolverTo(s *fakeDNS) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, s.addr)
		},
	}
}

// TestResolveAllIPsRacesSystemViewAgainstFallback covers the exposure this
// change fixes: a blackholed system resolver must not spend the dial budget
// before the configured fallback resolver is consulted. The answer is expected
// in milliseconds, while the blackholed leg's own per-attempt timeout is five
// seconds, so a sequential system-then-fallback order cannot pass the bound.
func TestResolveAllIPsRacesSystemViewAgainstFallback(t *testing.T) {
	system := newFakeDNS(t, fakeDNSBlackhole)
	fallback := newFakeDNS(t, fakeDNSAnswer)

	d := &directDialer{resolver: resolverTo(system), fallbackResolver: resolverTo(fallback)}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	start := time.Now()
	ips, err := d.resolveAllIPs(ctx, "node.example.com")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("resolveAllIPs: %v", err)
	}
	if len(ips) == 0 || ips[0] != "4.4.4.4" {
		t.Fatalf("expected the fallback resolver's IPv4 answer first, got %v", ips)
	}
	if elapsed > time.Second {
		t.Fatalf("resolution took %v: the blackholed system view was on the critical path", elapsed)
	}
}

// TestResolveAllIPsRacesFallbackAgainstHealthySystemView is the mirror case: a
// healthy system view still wins when the fallback resolver is the dead leg, so
// the race does not turn the configured fallback into the preferred resolver.
func TestResolveAllIPsRacesFallbackAgainstHealthySystemView(t *testing.T) {
	system := newFakeDNS(t, fakeDNSAnswer)
	fallback := newFakeDNS(t, fakeDNSBlackhole)

	d := &directDialer{resolver: resolverTo(system), fallbackResolver: resolverTo(fallback)}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	start := time.Now()
	ips, err := d.resolveAllIPs(ctx, "node.example.com")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("resolveAllIPs: %v", err)
	}
	if len(ips) == 0 || ips[0] != "4.4.4.4" {
		t.Fatalf("expected the system view's IPv4 answer first, got %v", ips)
	}
	if elapsed > time.Second {
		t.Fatalf("resolution took %v: the blackholed fallback was on the critical path", elapsed)
	}
}

// TestResolveAllIPsKeepsSystemResolverOnly covers the unconfigured case: with no
// fallback resolver there is nothing to race.
func TestResolveAllIPsKeepsSystemResolverOnly(t *testing.T) {
	system := newFakeDNS(t, fakeDNSAnswer)

	d := &directDialer{resolver: resolverTo(system)}

	ips, err := d.resolveAllIPs(context.Background(), "node.example.com")
	if err != nil {
		t.Fatalf("resolveAllIPs: %v", err)
	}
	if len(ips) == 0 || ips[0] != "4.4.4.4" {
		t.Fatalf("expected the system view's IPv4 answer first, got %v", ips)
	}
}

// failingResolver fails every query with text after delay. The DNSError a
// resolver returns names the /etc/resolv.conf server rather than the address
// actually dialed, so a distinctive failure text is the only way to tell the
// legs apart in the joined error.
func failingResolver(text string, delay time.Duration) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return nil, errors.New(text)
		},
	}
}

// TestResolveAllIPsJoinsLegErrorsInOrder covers the all-legs-failed path: the
// system view's diagnosis stays first even though the fallback leg reports its
// failure sooner, so the error message keeps naming the same resolver it named
// before the two legs were raced.
func TestResolveAllIPsJoinsLegErrorsInOrder(t *testing.T) {
	d := &directDialer{
		resolver:         failingResolver("system-leg-down", 50*time.Millisecond),
		fallbackResolver: failingResolver("fallback-leg-down", 0),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := d.resolveAllIPs(ctx, "node.example.com")
	if err == nil {
		t.Fatal("expected an error when both resolvers fail")
	}
	msg := err.Error()
	systemIdx := strings.Index(msg, "system-leg-down")
	fallbackIdx := strings.Index(msg, "fallback-leg-down")
	if systemIdx < 0 || fallbackIdx < 0 {
		t.Fatalf("expected both legs to be reported, got %q", msg)
	}
	if systemIdx > fallbackIdx {
		t.Fatalf("expected the system view's failure first, got %q", msg)
	}
}

// TestResolveHostUsesPackageLevelDialerPolicy covers the exported entry point
// setup-time callers use: it must resolve through the package-level Direct
// dialer, so the configured fallback resolver answers for a name the system view
// cannot resolve.
func TestResolveHostUsesPackageLevelDialerPolicy(t *testing.T) {
	fallback := newFakeDNS(t, fakeDNSAnswer)

	oldDirect := Direct
	Direct = NewDirectDialer(Option{FallbackDNS: fallback.addr})
	t.Cleanup(func() { Direct = oldDirect })

	// .invalid is guaranteed never to resolve (RFC 2606), so only the fallback
	// leg can produce an answer.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	start := time.Now()
	ips, err := ResolveHost(ctx, "race-probe.invalid")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	if len(ips) == 0 || ips[0] != "4.4.4.4" {
		t.Fatalf("expected the fallback resolver's IPv4 answer first, got %v", ips)
	}
	if elapsed > time.Second {
		t.Fatalf("resolution took %v: the fallback resolver was not raced", elapsed)
	}
}

// TestResolveHostRejectsForeignPackageDialer covers a package-level Direct that
// is not a direct dialer: the failure must be reported instead of silently
// falling back to a different resolution policy.
func TestResolveHostRejectsForeignPackageDialer(t *testing.T) {
	oldDirect := Direct
	Direct = foreignDialer{}
	t.Cleanup(func() { Direct = oldDirect })

	if _, err := ResolveHost(context.Background(), "node.example.com"); err == nil {
		t.Fatal("expected an error for a package-level dialer that carries no direct policy")
	}
}

type foreignDialer struct{}

func (foreignDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not a direct dialer")
}
func (foreignDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not a direct dialer")
}
func (foreignDialer) Alive() bool    { return true }
func (foreignDialer) Connect() error { return nil }
func (foreignDialer) Disconnect() error {
	return nil
}

// TestNewDirectDialerFallbackResolverOnlyWhenConfigured covers the leg count:
// only a configured fallback_resolver adds a second resolver. createResolver
// builds a system-view resolver from a bare mark, so keeping it would race a
// resolver against an identical copy of itself.
func TestNewDirectDialerFallbackResolverOnlyWhenConfigured(t *testing.T) {
	tests := []struct {
		name         string
		option       Option
		wantFallback bool
	}{
		{name: "no mark, no fallback", option: Option{}},
		{name: "mark, no fallback", option: Option{Mark: 0x1000}},
		{name: "fallback, no mark", option: Option{FallbackDNS: "8.8.8.8:53"}, wantFallback: true},
		{name: "mark and fallback", option: Option{Mark: 0x1000, FallbackDNS: "8.8.8.8:53"}, wantFallback: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, ok := NewDirectDialer(tt.option).(*directDialer)
			if !ok {
				t.Fatalf("unexpected dialer type %T", NewDirectDialer(tt.option))
			}
			if got := d.fallbackResolver != nil; got != tt.wantFallback {
				t.Fatalf("fallback resolver present = %v, want %v", got, tt.wantFallback)
			}
			if tt.option.Mark != 0 && d.resolver == nil {
				t.Fatal("a configured mark must select the marked system resolver")
			}
		})
	}
}

// TestResolveAllIPsHonoursCancellation covers the caller giving up: a canceled
// context must not wait for the blackholed leg.
func TestResolveAllIPsHonoursCancellation(t *testing.T) {
	system := newFakeDNS(t, fakeDNSBlackhole)
	fallback := newFakeDNS(t, fakeDNSBlackhole)

	d := &directDialer{resolver: resolverTo(system), fallbackResolver: resolverTo(fallback)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := d.resolveAllIPs(ctx, "node.example.com")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("canceled resolution took %v", elapsed)
	}
}
