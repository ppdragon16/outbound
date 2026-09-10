package bbrv3

import (
	"testing"
	"time"

	"github.com/daeuniverse/quic-go/congestion"
)

// ProbeRTT scheduling under the traffic patterns a proxy actually sees.
//
// The existing TestProbeRTTCycle drives the probe with an artificially drained
// sender. These tests cover what the README lists as not yet covered: an idle
// connection that resumes, a saturated sender that never drains on its own, a
// path change, and the periodicity of the probe over a long-lived connection.

// toSteadyState drives the sender out of STARTUP/DRAIN into ProbeBW.
func (h *harness) toSteadyState() {
	for i := 0; i < 30 && (h.s.state == stateStartup || h.s.state == stateDrain); i++ {
		h.round()
	}
}

// TestProbeRTTAfterIdleResume covers the bursty pattern: a connection that has
// been idle for longer than the probe interval must refresh its min RTT once
// traffic resumes, otherwise the BDP estimate stays inflated (and a queue stays
// standing) on the first packets after the gap.
func TestProbeRTTAfterIdleResume(t *testing.T) {
	h := newHarness(t)
	h.toSteadyState()
	before := h.s.minRtt
	if before == 0 {
		t.Fatal("min_rtt never measured")
	}

	// idle: no sends, no ACKs, for well over the probe interval
	h.clock.now = h.clock.now.Add(30 * time.Second)

	// traffic resumes; the probe must be scheduled now, not several seconds later
	var enteredAfter int
	for i := 1; i <= 3; i++ {
		h.round()
		if h.s.state == stateProbeRTT {
			enteredAfter = i
			break
		}
	}
	if enteredAfter == 0 {
		t.Fatalf("ProbeRTT was not entered within 3 rounds after resuming from idle (state %v, probeRttExpired %v, idleRestart %v)",
			h.s.state, h.s.probeRttExpired, h.s.idleRestart)
	}
	t.Logf("ProbeRTT entered %d round(s) after resuming", enteredAfter)

	// and it must still complete
	h.drainAll()
	h.clock.now = h.clock.now.Add(probeRTTDuration + 10*time.Millisecond)
	h.round()
	if h.s.state == stateProbeRTT {
		t.Fatalf("still in ProbeRTT after duration + a round following idle resume")
	}
}

// TestProbeRTTCompletesUnderContinuousUpload covers the sender that never runs
// dry: a proxy upload or a large download keeps the app-limited heuristic from
// firing, so the probe has to complete purely by draining in-flight through
// ACKs. A probe that cannot complete would leave the connection stuck at the
// clamped cwnd, i.e. at half throughput.
func TestProbeRTTCompletesUnderContinuousUpload(t *testing.T) {
	h := newHarness(t)
	h.toSteadyState()

	// let the probe interval expire, then keep the sender saturated
	h.clock.now = h.clock.now.Add(6 * time.Second)
	h.round()
	h.wantState(stateProbeRTT, "after probe_rtt expiry")

	// the probe state is visible as the reduced cwnd gain and the clamped window
	if h.s.cwndGain != probeRTTCwndGain {
		t.Fatalf("cwnd gain = %v during ProbeRTT, want %v", h.s.cwndGain, probeRTTCwndGain)
	}
	clamped := h.s.probeRTTCwnd()

	// keep sending and acknowledging: never drain manually
	var rounds int
	for rounds = 0; rounds < 20 && h.s.state == stateProbeRTT; rounds++ {
		h.round()
		// simulated time passes at the rate the ProbeRTT window needs
		h.clock.now = h.clock.now.Add(probeRTTDuration/2 + 1)
	}
	if h.s.state == stateProbeRTT {
		t.Fatalf("ProbeRTT did not complete within %d saturated rounds", rounds)
	}
	t.Logf("ProbeRTT completed after %d saturated rounds", rounds)

	// the window and gain saved on entry must be restored: leaving them at the
	// probe values would cap the connection at half of its capacity
	if h.s.cwndGain == probeRTTCwndGain {
		t.Fatalf("cwnd gain still %v after leaving ProbeRTT", h.s.cwndGain)
	}
	if h.s.cwnd < 4*mss {
		t.Fatalf("cwnd = %d (probe value %d) after ProbeRTT, want a usable window", h.s.cwnd, clamped)
	}
}

// TestProbeRTTScheduledPeriodically checks the probe is scheduled once per
// interval window over a long-lived connection: neither starved (stale min RTT)
// nor thrashed (a probe in every window).
func TestProbeRTTScheduledPeriodically(t *testing.T) {
	h := newHarness(t)
	h.toSteadyState()

	var entries int
	var lastEntry time.Time
	var minGap time.Duration = 1<<62 - 1
	for i := 0; i < 200; i++ {
		h.round()
		if h.s.state == stateProbeRTT {
			entries++
			gap := h.clock.now.Sub(lastEntry)
			if !lastEntry.IsZero() && gap < minGap {
				minGap = gap
			}
			lastEntry = h.clock.now
			// leave the state so the next round can be observed again
			for h.s.state == stateProbeRTT {
				h.drainAll()
				h.clock.now = h.clock.now.Add(probeRTTDuration + 10*time.Millisecond)
				h.round()
			}
		}
	}
	elapsed := h.clock.now
	t.Logf("%d ProbeRTT windows over %v (min gap %v)", entries, elapsed, minGap)
	if entries < 2 {
		t.Fatalf("only %d ProbeRTT windows in %v: the probe is not scheduled periodically", entries, elapsed)
	}
	// the draft schedules a probe once per ProbeRTTInterval; allow slack for
	// rounds that are spent inside a previous probe window
	if minGap < probeRTTInterval/2 {
		t.Fatalf("ProbeRTT windows only %v apart: the probe is thrashing (interval %v)", minGap, probeRTTInterval)
	}
}

// TestProbeRTTOnHighBDPLink covers a fast path, where 0.5*BDP is a large cwnd:
// the probe must still be able to drain in-flight and complete.
func TestProbeRTTOnHighBDPLink(t *testing.T) {
	h := newHarness(t)
	// a bottleneck delivering 400 MSS per 50ms round (~77 Mbps)
	for i := 0; i < 30 && (h.s.state == stateStartup || h.s.state == stateDrain); i++ {
		h.fill()
		h.event(400, 0)
	}
	if h.s.fullBwReached == false {
		t.Logf("note: full_bw not reached yet, continuing anyway")
	}
	h.clock.now = h.clock.now.Add(6 * time.Second)
	h.fill()
	h.event(400, 0)
	if h.s.state != stateProbeRTT {
		t.Fatalf("ProbeRTT not entered on a high-BDP link (state %v)", h.s.state)
	}
	clamped := h.s.probeRTTCwnd()
	if clamped < 4*mss {
		t.Fatalf("probe_rtt cwnd %d below the minimum pipe size", clamped)
	}
	var rounds int
	for rounds = 0; rounds < 20 && h.s.state == stateProbeRTT; rounds++ {
		h.fill()
		h.event(400, 0)
		h.clock.now = h.clock.now.Add(probeRTTDuration/2 + 1)
	}
	if h.s.state == stateProbeRTT {
		t.Fatalf("ProbeRTT did not complete on a high-BDP link within %d rounds (cwnd %d, clamped %d)",
			rounds, h.s.cwnd, clamped)
	}
	t.Logf("ProbeRTT completed on high-BDP link after %d rounds", rounds)
}

// eventAfter is a congestion event that advances the clock by an arbitrary RTT,
// which is how a path change is modelled.
func (h *harness) eventAfter(d time.Duration, n, m int) {
	total := n + m
	if total > len(h.outstanding) {
		total = len(h.outstanding)
	}
	if total == 0 {
		return
	}
	h.clock.now = h.clock.now.Add(d)
	eventTime := h.clock.now
	prior := h.inflight
	var acked []congestion.AckedPacketInfo
	var lost []congestion.LostPacketInfo
	for i := 0; i < total; i++ {
		o := h.outstanding[i]
		if i < n {
			acked = append(acked, congestion.AckedPacketInfo{PacketNumber: o.pn, BytesAcked: o.size})
			h.inflight -= o.size
		} else {
			lost = append(lost, congestion.LostPacketInfo{PacketNumber: o.pn, BytesLost: o.size})
			h.inflight -= o.size
		}
	}
	h.outstanding = h.outstanding[total:]
	h.s.bytesInFlight = prior
	for _, a := range acked {
		h.s.bytesInFlight -= a.BytesAcked
	}
	for _, l := range lost {
		h.s.bytesInFlight -= l.BytesLost
	}
	h.s.OnCongestionEventEx(prior, eventTime, acked, lost)
}

// TestMinRTTFollowsAPathChange covers the reason the probe and its min-RTT filter
// exist: when the path changes, the BDP estimate has to follow, otherwise the
// sender keeps filling a queue that is no longer there (or undershoots).
func TestMinRTTFollowsAPathChange(t *testing.T) {
	h := newHarness(t)
	h.toSteadyState()
	oldMin := h.s.minRtt
	if oldMin == 0 {
		t.Fatal("min_rtt never measured")
	}

	// Path improves: RTT drops from 50ms to 20ms. Drain first, so that the
	// RTT samples only cover packets sent on the new path (rate samples mix the
	// send states of the packets being acknowledged).
	h.drainAll()
	for i := 0; i < 5; i++ {
		h.fill()
		h.eventAfter(20*time.Millisecond, ackPerRound, 0)
	}
	if h.s.minRtt >= oldMin {
		t.Fatalf("min_rtt did not follow the improved path: %v (was %v)", h.s.minRtt, oldMin)
	}
	improved := h.s.minRtt
	t.Logf("min_rtt followed the improved path: %v -> %v", oldMin, improved)

	// Path degrades: RTT rises to 150ms. BBR keeps the minimum for the filter
	// window (10s), so min_rtt must not jump immediately...
	h.drainAll()
	for i := 0; i < 5; i++ {
		h.fill()
		h.eventAfter(150*time.Millisecond, ackPerRound, 0)
	}
	if h.s.minRtt != improved {
		t.Fatalf("min_rtt jumped to %v after a short RTT increase, want it held at %v for the filter window",
			h.s.minRtt, improved)
	}
	// ...but it must follow once the filter window expired (10s, i.e. more than
	// 67 rounds at 150ms).
	for i := 0; i < 100; i++ {
		h.fill()
		h.eventAfter(150*time.Millisecond, ackPerRound, 0)
	}
	if h.s.minRtt <= improved {
		t.Fatalf("min_rtt = %v never followed the degraded path (was %v)", h.s.minRtt, improved)
	}
	t.Logf("min_rtt followed the degraded path: %v -> %v", improved, h.s.minRtt)
}
