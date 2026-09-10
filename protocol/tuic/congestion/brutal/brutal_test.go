package brutal

import (
	"math"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go/congestion"
)

// fakeClock drives the jitter window deterministically.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

const testBps = congestion.ByteCount(8_000_000) // 8 MB/s

func newTestSender(t *testing.T, jitterPct float64, window time.Duration, limit congestion.ByteCount) (*BrutalSender, *fakeClock) {
	t.Helper()
	bs := newBrutalSender(uint64(testBps), false, jitterPct, window, limit)
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	bs.now = clock.Now
	return bs, clock
}

// TestTargetRateWithoutJitter pins the behaviour brutal had before rate
// randomisation existed: exactly bps / ackRate.
func TestTargetRateWithoutJitter(t *testing.T) {
	bs, _ := newTestSender(t, 0, time.Second, 0)
	if got := bs.targetRate(); got != testBps {
		t.Fatalf("target rate = %d, want %d", got, testBps)
	}
	bs.ackRate = 0.8
	want := congestion.ByteCount(float64(testBps) / 0.8)
	if got := bs.targetRate(); got != want {
		t.Fatalf("target rate with loss compensation = %d, want %d", got, want)
	}
}

// TestJitterStaysWithinBounds checks the factor never leaves [1-J, 1+J].
func TestJitterStaysWithinBounds(t *testing.T) {
	const pct = 0.1
	bs, clock := newTestSender(t, pct, time.Second, 0)

	lo := congestion.ByteCount(float64(testBps) * (1 - pct))
	hi := congestion.ByteCount(float64(testBps) * (1 + pct))
	for i := 0; i < 1000; i++ {
		clock.now = clock.now.Add(time.Second)
		got := bs.targetRate()
		if got < lo || got > hi {
			t.Fatalf("rate %d outside [%d, %d] (iteration %d)", got, lo, hi, i)
		}
	}
}

// TestJitterKeepsTheAverageRate is the property that makes the mitigation
// acceptable for brutal's purpose: the configured rate is still the average, so
// a connection tuned to just below saturation stays there over time.
func TestJitterKeepsTheAverageRate(t *testing.T) {
	const pct = 0.1
	bs, clock := newTestSender(t, pct, time.Second, 0)

	const windows = 20000
	var sum float64
	for i := 0; i < windows; i++ {
		clock.now = clock.now.Add(time.Second)
		sum += float64(bs.targetRate())
	}
	avg := sum / windows
	dev := math.Abs(avg-float64(testBps)) / float64(testBps)
	// uniform ±10%: the standard error over 20k samples is far below 1%
	if dev > 0.01 {
		t.Fatalf("average rate %.0f deviates %.2f%% from the configured %d", avg, dev*100, testBps)
	}
}

// TestJitterIsStableWithinAWindowAndChangesBetweenWindows checks the factor is
// re-drawn per window rather than per call: jitter that changes on every pacing
// decision would just add noise without changing the long-term signature.
func TestJitterIsStableWithinAWindowAndChangesBetweenWindows(t *testing.T) {
	bs, clock := newTestSender(t, 0.1, time.Second, 0)

	first := bs.targetRate()
	for i := 0; i < 100; i++ {
		clock.now = clock.now.Add(time.Millisecond)
		if got := bs.targetRate(); got != first {
			t.Fatalf("rate changed within the window: %d -> %d", first, got)
		}
	}

	changed := 0
	for i := 0; i < 20; i++ {
		clock.now = clock.now.Add(time.Second)
		if bs.targetRate() != first {
			changed++
		}
	}
	if changed < 10 {
		t.Fatalf("rate stayed at %d in %d of 20 windows: the factor is not re-drawn", first, 20-changed)
	}
}

// TestJitterNeverExceedsTheLossCompensationPeak is the safety property: turning
// randomisation on must not raise the peak rate a connection can reach, so the
// ceiling stays at the worst case the loss compensation already had.
func TestJitterNeverExceedsTheLossCompensationPeak(t *testing.T) {
	bs, clock := newTestSender(t, 0.1, time.Second, 0)
	bs.ackRate = minAckRate // worst case: maximum loss compensation

	ceiling := congestion.ByteCount(float64(testBps) / minAckRate)
	for i := 0; i < 1000; i++ {
		clock.now = clock.now.Add(time.Second)
		if got := bs.targetRate(); got > ceiling {
			t.Fatalf("rate %d exceeds the compensation peak %d", got, ceiling)
		}
	}
}

// TestRateLimitCapsTheRate checks the explicit ceiling, which is the knob for
// bounding what brutal will ever put on the wire.
func TestRateLimitCapsTheRate(t *testing.T) {
	limit := congestion.ByteCount(2_000_000)
	bs, clock := newTestSender(t, 0.1, time.Second, limit)
	bs.ackRate = minAckRate

	for i := 0; i < 1000; i++ {
		clock.now = clock.now.Add(time.Second)
		if got := bs.targetRate(); got > limit {
			t.Fatalf("rate %d exceeds the configured limit %d", got, limit)
		}
	}

	// and the sender falls back to the derived cap when the limit is cleared
	bs.SetRateLimit(0)
	if got := bs.rateCeiling(); got != congestion.ByteCount(float64(testBps)/minAckRate) {
		t.Fatalf("ceiling after clearing the limit = %d", got)
	}
}

// TestRateLimitAboveTheConfiguredRateIsInert documents that a limit above what
// the sender would send anyway changes nothing.
func TestRateLimitAboveTheConfiguredRateIsInert(t *testing.T) {
	bs, _ := newTestSender(t, 0, time.Second, testBps*10)
	if got := bs.targetRate(); got != testBps {
		t.Fatalf("rate = %d, want the configured %d", got, testBps)
	}
}

// TestEnvDefaults checks the environment switches, including the guard rails on
// nonsensical values.
func TestEnvDefaults(t *testing.T) {
	t.Setenv(jitterPctEnv, "")
	if got := envJitterPct(); got != defaultJitterPct/100 {
		t.Fatalf("default jitter = %v", got)
	}
	t.Setenv(jitterPctEnv, "0")
	if got := envJitterPct(); got != 0 {
		t.Fatalf("jitter for \"0\" = %v, want disabled", got)
	}
	t.Setenv(jitterPctEnv, "not-a-number")
	if got := envJitterPct(); got != defaultJitterPct/100 {
		t.Fatalf("jitter for a malformed value = %v, want the default", got)
	}
	t.Setenv(jitterPctEnv, "150")
	if got := envJitterPct(); got != 0.9 {
		t.Fatalf("jitter for \"150\" = %v, want it clamped to 0.9", got)
	}

	t.Setenv(jitterWindowEnv, "250ms")
	if got := envJitterWindow(); got != 250*time.Millisecond {
		t.Fatalf("window = %v", got)
	}
	t.Setenv(jitterWindowEnv, "-1s")
	if got := envJitterWindow(); got != defaultJitterWindow {
		t.Fatalf("window for a negative value = %v, want the default", got)
	}

	t.Setenv(maxRateEnv, "1048576")
	if got := envRateLimit(); got != 1048576 {
		t.Fatalf("rate limit = %d", got)
	}
	t.Setenv(maxRateEnv, "bogus")
	if got := envRateLimit(); got != 0 {
		t.Fatalf("rate limit for a malformed value = %d, want 0", got)
	}
}

// TestPacerAchievesTheJitteredRate simulates the sender's loop and measures what
// the pacer actually puts on the wire. The jitter must not change the rate a
// connection achieves over time -- brutal exists to hold a known link just
// below saturation, and that property must survive the mitigation.
func TestPacerAchievesTheJitteredRate(t *testing.T) {
	const bps = congestion.ByteCount(10_000_000)
	bs := newBrutalSender(uint64(bps), false, 0.1, time.Second, 0)
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	bs.now = clock.Now
	bs.ackRate = 1

	achieved := simulateSend(bs, clock, 30*time.Second)
	dev := math.Abs(achieved-float64(bps)) / float64(bps)
	if dev > 0.02 {
		t.Fatalf("achieved rate %.0f deviates %.2f%% from the configured %d", achieved, dev*100, bps)
	}
}

// TestPacerRespectsTheRateLimit is the same simulation with a ceiling: what the
// sender puts on the wire must stay below the limit even though the loss
// compensation and the jitter would both push above it.
func TestPacerRespectsTheRateLimit(t *testing.T) {
	const bps = congestion.ByteCount(10_000_000)
	const limit = congestion.ByteCount(4_000_000)

	bs := newBrutalSender(uint64(bps), false, 0.1, time.Second, limit)
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	bs.now = clock.Now
	bs.ackRate = minAckRate // maximum loss compensation

	achieved := simulateSend(bs, clock, 30*time.Second)
	if achieved > float64(limit)*1.02 {
		t.Fatalf("achieved rate %.0f exceeds the configured limit %d", achieved, limit)
	}
	if achieved < float64(limit)*0.5 {
		t.Fatalf("achieved rate %.0f is far below the configured limit %d", achieved, limit)
	}
}

// simulateSend drives the pacer like the connection would and returns the
// average rate in bytes per second.
func simulateSend(bs *BrutalSender, clock *fakeClock, duration time.Duration) float64 {
	const (
		step       = 100 * time.Microsecond
		packetSize = congestion.ByteCount(1200)
	)
	start := clock.now
	end := start.Add(duration)
	var sent congestion.ByteCount
	for now := start; now.Before(end); now = now.Add(step) {
		clock.now = now
		if bs.pacer.Budget(now) >= packetSize {
			bs.pacer.SentPacket(now, packetSize)
			sent += packetSize
		}
	}
	return float64(sent) / end.Sub(start).Seconds()
}
