package bbrv3

import (
	"testing"
	"time"

	"github.com/daeuniverse/quic-go/congestion"
)

const (
	mss         = congestion.ByteCount(1200)
	roundRTT    = 50 * time.Millisecond
	ackPerRound = 40 // fixed delivery: 40 MSS / 50 ms = 7.68 Mbps bottleneck
)

// ----------------------------------------------------------- test harness

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

type fakeRTTStats struct{ srtt time.Duration }

func (f *fakeRTTStats) MinRTT() time.Duration        { return f.srtt }
func (f *fakeRTTStats) LatestRTT() time.Duration     { return f.srtt }
func (f *fakeRTTStats) SmoothedRTT() time.Duration   { return f.srtt }
func (f *fakeRTTStats) MeanDeviation() time.Duration { return 0 }
func (f *fakeRTTStats) MaxAckDelay() time.Duration   { return 0 }
func (f *fakeRTTStats) PTO(bool) time.Duration       { return f.srtt }
func (f *fakeRTTStats) UpdateRTT(_, _ time.Duration) {}
func (f *fakeRTTStats) SetMaxAckDelay(time.Duration) {}
func (f *fakeRTTStats) SetInitialRTT(time.Duration)  {}

type outstanding struct {
	pn   congestion.PacketNumber
	size congestion.ByteCount
}

// harness emulates a data-rich sender over a fixed-rate bottleneck:
// each round refills in-flight to cwnd (so the app-limited heuristic never
// fires, matching a saturated sender) and delivers a fixed number of packets
// per RTT (so delivery-rate samples plateau).
type harness struct {
	t           *testing.T
	s           *bbr3Sender
	clock       *fakeClock
	pn          congestion.PacketNumber
	inflight    congestion.ByteCount
	outstanding []outstanding
}

func newHarness(t *testing.T) *harness {
	clock := &fakeClock{now: time.Unix(0, 0)}
	s := NewBbr3Sender(clock, mss)
	s.SetRTTStatsProvider(&fakeRTTStats{srtt: roundRTT})
	return &harness{t: t, s: s, clock: clock}
}

func (h *harness) send(n int) {
	for i := 0; i < n; i++ {
		h.pn++
		// The fork's sentPacketHandler adds size to bytesInFlight before the
		// callback, so the parameter includes the current packet.
		h.inflight += mss
		h.s.OnPacketSent(h.clock.now, h.inflight, h.pn, mss, true)
		h.outstanding = append(h.outstanding, outstanding{pn: h.pn, size: mss})
	}
}

// loseByTimer declares the oldest n outstanding packets lost via the legacy
// OnCongestionEvent callback (loss-detection-timer path, RACK tail loss).
func (h *harness) loseByTimer(n int) {
	if n > len(h.outstanding) {
		n = len(h.outstanding)
	}
	var lost []congestion.LostPacketInfo
	for i := 0; i < n; i++ {
		o := h.outstanding[i]
		lost = append(lost, congestion.LostPacketInfo{PacketNumber: o.pn, BytesLost: o.size})
		h.inflight -= o.size
	}
	h.outstanding = h.outstanding[n:]
	for _, l := range lost {
		h.s.OnCongestionEvent(l.PacketNumber, l.BytesLost, h.inflight)
	}
}

// fill tops up in-flight to the congestion window (saturated sender).
func (h *harness) fill() {
	for h.inflight < h.s.GetCongestionWindow() {
		h.send(1)
	}
}

// eventAt delivers one congestion event: ack the oldest n outstanding
// packets and declare the following m lost, at now+rtt.
func (h *harness) event(n, m int) {
	total := n + m
	if total > len(h.outstanding) {
		total = len(h.outstanding)
	}
	if total == 0 {
		return
	}
	h.clock.now = h.clock.now.Add(roundRTT)
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
	// Mirror the fork's accounting: the CC sees priorInFlight and updates its
	// local inflight by subtracting acked/lost.
	h.s.bytesInFlight = prior
	for _, a := range acked {
		h.s.bytesInFlight -= a.BytesAcked
	}
	for _, l := range lost {
		h.s.bytesInFlight -= l.BytesLost
	}
	h.s.OnCongestionEventEx(prior, eventTime, acked, lost)
}

// round = saturated fill + fixed-rate delivery (bw plateau).
func (h *harness) round() {
	h.fill()
	h.event(ackPerRound, 0)
}

func (h *harness) drainAll() {
	h.event(len(h.outstanding), 0)
}

func (h *harness) wantState(want bbr3State, msg string) {
	h.t.Helper()
	if h.s.state != want {
		h.t.Fatalf("%s: state = %v, want %v", msg, h.s.state, want)
	}
}

// ------------------------------------------------------------------- tests

// TestInitialPacingRate: draft §5.6.2 InitPacingRate —
// C.pacing_rate = StartupPacingGain * (InitialCwnd / srtt).
// BandwidthFromDelta yields bits/s; bandwidthForPacer converts to bytes/s.
func TestInitialPacingRate(t *testing.T) {
	h := newHarness(t)
	bps := h.s.bandwidthForPacer()
	want := congestion.ByteCount(startupPacingGain * float64(h.s.initialCwnd) / roundRTT.Seconds())
	if bps < minBps {
		t.Fatalf("pacer bandwidth %d below floor", bps)
	}
	if bps != want {
		t.Fatalf("pacer bandwidth = %d, want %d", bps, want)
	}
}

// TestStartupExitsOnBandwidthPlateau: full-pipe estimator (draft §5.3.1.2) —
// three rounds without 25% delivery-rate growth set full_bw_reached → Drain.
func TestStartupExitsOnBandwidthPlateau(t *testing.T) {
	h := newHarness(t)
	h.wantState(stateStartup, "initial")
	for i := 0; i < 12 && h.s.state == stateStartup; i++ {
		h.round()
	}
	if !h.s.fullBwReached {
		t.Fatalf("full_bw_reached not set after plateau rounds (fullCnt=%d appLim=%v)",
			h.s.fullBwCount, h.s.sampler.IsAppLimited())
	}
	h.wantState(stateDrain, "after plateau")
}

// TestStartupExitsOnHighLoss: CheckStartupHighLoss (draft §5.3.1.3) — ≥6
// losses in a round with >2% loss rate exits Startup, sets inflight_longterm
// and enters Drain. Delivery rate grows each round so the bw-plateau exit
// never fires first.
func TestStartupExitsOnHighLoss(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 4; i++ {
		// Growing delivery keeps full_bw from latching.
		h.fill()
		h.event(ackPerRound+i*12, 0)
	}
	if h.s.state != stateStartup {
		t.Fatalf("premature startup exit, state=%v", h.s.state)
	}
	// Loss round: 6 lost packets (>2% of send-time inflight).
	h.fill()
	h.event(ackPerRound, 6)
	if h.s.fullBwReached {
		t.Fatalf("startup exited before the loss round completed")
	}
	// The next events complete a full round trip since the first loss; the
	// ack-oldest harness needs a few events before the loss round's
	// delivery boundary is crossed.
	for i := 0; i < 8 && !h.s.fullBwReached; i++ {
		h.fill()
		h.event(ackPerRound, 0)
	}
	if !h.s.fullBwReached {
		t.Fatalf("full_bw_reached not set by CheckStartupHighLoss (lostRound=%dB cnt=%d maxTx=%d)",
			h.s.bytesLostInRound, h.s.lossCountInRound, h.s.maxLossTxInFlight)
	}
	if h.s.inflightLongterm == infByteCount {
		t.Fatalf("inflight_longterm not set by CheckStartupHighLoss")
	}
	h.wantState(stateDrain, "after high loss")
}

// TestDrainExitsToProbeBW: CheckDrainDone (draft L2368-2372) — ProbeBW
// starts at DOWN with the 0.90 pacing gain (§5.6.1 table).
func TestDrainExitsToProbeBW(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 12 && h.s.state == stateStartup; i++ {
		h.round()
	}
	if h.s.state != stateDrain {
		t.Fatalf("never entered Drain, state=%v", h.s.state)
	}
	for i := 0; i < 16 && h.s.state == stateDrain; i++ {
		h.round()
	}
	h.wantState(stateProbeBWDown, "after drain")
	if h.s.pacingGain != probeDownPacingGain {
		t.Fatalf("DOWN pacing gain = %v, want %v", h.s.pacingGain, probeDownPacingGain)
	}
	if h.s.cwndGain != defaultCwndGain {
		t.Fatalf("DOWN cwnd gain = %v, want %v", h.s.cwndGain, defaultCwndGain)
	}
}

// driveToUp moves the machine from ProbeBW_DOWN through REFILL into UP.
func driveToUp(h *harness) {
	for i := 0; i < 20 && h.s.state != stateProbeBWDown; i++ {
		h.round()
	}
	for i := 0; i < 6 && h.s.state == stateDrain; i++ {
		h.round()
	}
	if h.s.state != stateProbeBWDown {
		return
	}
	// 3.5s: past the random bw_probe_wait upper bound (2-3s) but before the
	// 5s probe_rtt expiry, so the DOWN→REFILL transition isn't preempted.
	h.clock.now = h.clock.now.Add(3500 * time.Millisecond)
	h.fill()
	h.event(1, 0) // DOWN → REFILL (draft L2806-2811)
	// One round of REFILL → UP (draft L2938-2942). round_start advances on
	// alternating events in this harness (fill-then-ack-oldest), so loop.
	for i := 0; i < 4 && h.s.state == stateProbeBWRefill; i++ {
		h.fill()
		h.event(ackPerRound, 0)
	}
}

// TestProbeBWDownToRefillToUp: time-scale probing (§5.3.3.8) and UP gains
// (1.25 pacing / 2.25 cwnd, §5.6.1 table).
func TestProbeBWDownToRefillToUp(t *testing.T) {
	h := newHarness(t)
	driveToUp(h)
	h.wantState(stateProbeBWUp, "after refill round")
	if h.s.pacingGain != probeUpPacingGain {
		t.Fatalf("UP pacing gain = %v, want %v", h.s.pacingGain, probeUpPacingGain)
	}
	if h.s.cwndGain != probeUpCwndGain {
		t.Fatalf("UP cwnd gain = %v, want %v", h.s.cwndGain, probeUpCwndGain)
	}
}

// TestProbeUpEndsOnHighLoss: IsInflightTooHigh/HandleInflightTooHigh (draft
// §5.5.10.2) — >2% loss during UP sets inflight_longterm, returns to DOWN
// and bounds cwnd (BoundCwndForModel, draft L4627-4639).
func TestProbeUpEndsOnHighLoss(t *testing.T) {
	h := newHarness(t)
	driveToUp(h)
	if h.s.state != stateProbeBWUp {
		t.Fatalf("precondition: state = %v, want UP", h.s.state)
	}
	if !h.s.isBwProbeSample {
		t.Fatalf("is_bw_probe_sample not set in UP")
	}
	h.fill()
	h.event(ackPerRound-8, 8)
	if !h.s.prevProbeTooHigh {
		t.Fatalf("prev_probe_too_high not set")
	}
	if h.s.inflightLongterm == infByteCount {
		t.Fatalf("inflight_longterm not set by HandleInflightTooHigh")
	}
	h.wantState(stateProbeBWDown, "after probe-too-high")
	if h.s.cwnd > h.s.inflightLongterm {
		t.Fatalf("cwnd %d exceeds inflight_longterm %d", h.s.cwnd, h.s.inflightLongterm)
	}
}

// TestProbeRTTCycle: UpdateMinRTT/CheckProbeRTT (draft §5.3.4.3) — entry
// once probe_rtt_min_delay expires (5s), cwnd clamped by ProbeRTTCwndGain
// 0.5, exit to ProbeBW after 200ms + one round.
func TestProbeRTTCycle(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 12 && h.s.state == stateStartup; i++ {
		h.round()
	}
	for i := 0; i < 6 && h.s.state == stateDrain; i++ {
		h.round()
	}
	if h.s.minRtt == 0 {
		t.Fatalf("min_rtt never measured")
	}
	// Let probe_rtt_min_delay expire, then deliver an ACK carrying RTT.
	h.clock.now = h.clock.now.Add(6 * time.Second)
	h.fill()
	h.event(ackPerRound, 0)
	h.wantState(stateProbeRTT, "after probe_rtt expiry")
	if h.s.cwndGain != probeRTTCwndGain {
		t.Fatalf("ProbeRTT cwnd gain = %v, want %v", h.s.cwndGain, probeRTTCwndGain)
	}

	// ProbeRTT holds until inflight drains, 200ms elapse and a round passes.
	h.drainAll()
	h.clock.now = h.clock.now.Add(probeRTTDuration + 10*time.Millisecond)
	h.send(2)
	h.event(2, 0)
	if h.s.state == stateProbeRTT {
		t.Fatalf("still in ProbeRTT after duration + round")
	}
	if h.s.state != stateProbeBWCruise {
		t.Fatalf("state = %v, want CRUISE after ProbeRTT (full_bw already reached)", h.s.state)
	}
}

// TestPacingRateFollowsGain: SetPacingRateWithGain (draft L4291-4294) —
// after full_bw_reached the pacer tracks pacing_gain * bw * 99%.
func TestPacingRateFollowsGain(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 12 && h.s.state == stateStartup; i++ {
		h.round()
	}
	if !h.s.fullBwReached {
		t.Fatalf("precondition failed: full_bw not reached")
	}
	want := congestion.ByteCount(h.s.pacingGain * pacingMargin * float64(h.s.bw) / 8)
	got := h.s.bandwidthForPacer()
	if got < want*99/100 || got > want*101/100 {
		t.Fatalf("pacer bandwidth = %d, want ≈ %d (pacing_gain=%v bw=%d)",
			got, want, h.s.pacingGain, h.s.bw)
	}
}

// TestSamplerLostSendStates: the sampler extension feeding the draft's
// HandleLostPacket exposes per-lost-packet send states with sizes and
// send-time in-flight (draft §5.5.10.2 uses both).
func TestSamplerLostSendStates(t *testing.T) {
	h := newHarness(t)
	h.send(10)
	h.clock.now = h.clock.now.Add(roundRTT)
	var acked []congestion.AckedPacketInfo
	var lost []congestion.LostPacketInfo
	for i, o := range h.outstanding {
		if i < 6 {
			acked = append(acked, congestion.AckedPacketInfo{PacketNumber: o.pn, BytesAcked: o.size})
		} else {
			lost = append(lost, congestion.LostPacketInfo{PacketNumber: o.pn, BytesLost: o.size})
		}
	}
	sample := h.s.sampler.OnCongestionEvent(h.clock.now, acked, lost, h.s.maxBw(), infBandwidth, h.s.roundCount)
	if len(sample.lostSendStates) != 4 {
		t.Fatalf("lostSendStates = %d, want 4", len(sample.lostSendStates))
	}
	for i, st := range sample.lostSendStates {
		if !st.isValid {
			t.Fatalf("lostSendStates[%d] invalid", i)
		}
		if st.size != mss {
			t.Fatalf("lostSendStates[%d].size = %d, want %d", i, st.size, mss)
		}
		if st.bytesInFlight == 0 {
			t.Fatalf("lostSendStates[%d].bytesInFlight = 0 (tx_in_flight unusable)", i)
		}
	}
}

// TestTimerLossPath: losses declared by the loss-detection timer (legacy
// OnCongestionEvent callback) must fold into the loss model on the next ACK
// event, and the sampler must count them consistently.
func TestTimerLossPath(t *testing.T) {
	h := newHarness(t)
	h.send(20)
	h.clock.now = h.clock.now.Add(roundRTT)
	h.loseByTimer(3)
	if !h.s.sampler.IsAppLimited() && h.s.sampler.TotalBytesLost() != 3*mss {
		t.Fatalf("sampler totalBytesLost = %d, want %d", h.s.sampler.TotalBytesLost(), 3*mss)
	}
	if len(h.s.pendingLosses) != 3 {
		t.Fatalf("pendingLosses = %d, want 3", len(h.s.pendingLosses))
	}
	if h.s.isLossInRound {
		t.Fatalf("loss registered before the next ACK event")
	}
	// The next ACK event drains the queue into the loss model.
	h.fill()
	h.event(10, 0)
	if !h.s.isLossInRound {
		t.Fatalf("pending losses not folded into the loss model")
	}
	if h.s.bytesLostInRound != 3*mss {
		t.Fatalf("bytesLostInRound = %d, want %d", h.s.bytesLostInRound, 3*mss)
	}
	if h.s.lossCountInRound != 3 {
		t.Fatalf("lossCountInRound = %d, want 3", h.s.lossCountInRound)
	}
	if len(h.s.pendingLosses) != 0 {
		t.Fatalf("pendingLosses = %d after drain, want 0", len(h.s.pendingLosses))
	}
}

// TestInflightAtLossClamp: InflightAtLoss (draft L3954-3964) must not go
// negative when the lost fraction already exceeds the threshold.
func TestInflightAtLossClamp(t *testing.T) {
	h := newHarness(t)
	st := sendTimeState{isValid: true, bytesInFlight: mss, size: mss}
	rs := &rateSample{txInFlight: mss, lost: mss, valid: true}
	if got := h.s.inflightAtLoss(&st, rs); got < 0 {
		t.Fatalf("inflightAtLoss = %d, must be clamped ≥ 0", got)
	}
}

// TestAppLimitedPacingAware: the app-limited approximation must judge against
// what pacing sustains (capped by cwnd), not cwnd alone — in ProbeBW the
// pacer holds ~1 BDP in flight while cwnd allows ~2×BDP, and a cwnd-relative
// test would mark every steady event app-limited and starve the model.
func TestAppLimitedPacingAware(t *testing.T) {
	h := newHarness(t)
	driveToUp(h) // UP: pacingRate ≈ 1.25×bw, minRtt = 50ms, BDP = 48000B

	// Pacing-sustained in-flight (~60KB at 1.25×bw × 50ms) must NOT be
	// flagged, even though it is far below the UP cwnd (~108KB).
	h.drainAll()
	h.send(50) // 60000 B ≈ 1.25 BDP
	h.clock.now = h.clock.now.Add(roundRTT)
	h.event(40, 0)
	if h.s.sampler.IsAppLimited() {
		t.Fatalf("pacing-sustained inflight (%dB) marked app-limited", h.inflight)
	}

	// Genuine idleness must still be flagged.
	h.drainAll()
	h.send(5) // 6000 B, well under 3/4 of pacing-sustained in-flight
	h.clock.now = h.clock.now.Add(roundRTT)
	h.event(1, 0)
	if !h.s.sampler.IsAppLimited() {
		t.Fatalf("near-idle inflight (%dB) not marked app-limited", h.inflight)
	}
}
