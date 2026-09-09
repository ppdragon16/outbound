// Package bbrv3 implements BBRv3 congestion control (draft-ietf-ccwg-bbr-06)
// as a pluggable congestion controller for github.com/daeuniverse/quic-go.
//
// The state machine follows the pseudocode in draft-ietf-ccwg-bbr-06 §5
// (comments cite draft line numbers / section numbers). The data plane
// (delivery-rate sampler, windowed filters, packet-number queue) is carried
// over from the sibling TUIC BBRv1 package (Chromium QUIC lineage), extended
// with per-lost-packet send states and packet sizes so that the draft's
// loss model (§5.5.10.2) can be implemented precisely.
//
// Deliberate deviations from the draft (each documented inline as well):
//   - ECN: not implemented. The draft leaves ECN response unspecified (§3.7)
//     and the quic-go fork does not pass ECN-CE counts to congestion control.
//   - Spurious-loss undo (§5.5.11): not implemented; the transport never
//     notifies us of spurious recovery. quiche's Bbr3Sender has the same TODO.
//   - C.has_selective_acks is always true (QUIC ACK ranges are selective).
//   - Loss-recovery cwnd modulation (§5.6.4.4): no recovery hooks exist in
//     the fork's congestion interface, so InRecovery() is always false
//     (same as quiche's Bbr3Sender). Loss responses happen purely through
//     the model updates in §5.5.10.
//   - OnRetransmissionTimeout: no-op. The fork never invokes it (it is dead
//     code in the adapter), and quiche's Bbr3Sender ignores it too.
//   - C.is_cwnd_limited is approximated at OnPacketSent time
//     (bytesInFlight+bytes > cwnd), since the interface lacks the signal.
package bbrv3

import (
	"fmt"
	"net"
	"time"

	rand "github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion/common"
	"github.com/daeuniverse/quic-go/congestion"
)

const (
	minBps = 65536 // 64 kbps; pacer floor (see bandwidthForPacer)

	invalidPacketNumber            = -1
	initialCongestionWindowPackets = 32

	// draft §2.5/§2.6: startup/drain gains.
	startupPacingGain = 2.77 // BBRStartupPacingGain (4*ln 2)
	drainPacingGain   = 0.5  // BBRDrainPacingGain
	// draft §5.6.1 control-behavior table (L4212-4236).
	probeDownPacingGain = 0.90
	probeUpPacingGain   = 1.25
	probeUpCwndGain     = 2.25
	defaultCwndGain     = 2.0 // BBRStartupCwndGain / DefaultCwndGain
	probeRTTCwndGain    = 0.5 // BBRProbeRTTCwndGain (§2.16.2, L794)

	// draft §2.8 core design parameters.
	lossThresh = 0.02 // BBR.LossThresh
	beta       = 0.7  // BBR.Beta
	headroom   = 0.15 // BBR.Headroom
	// BBRStartupFullLossCnt (§5.3.1.3, L2307).
	startupFullLossCount = 6

	// draft §2.16.1/§2.16.2.
	minRTTFilterLen  = 10 * time.Second       // BBR.MinRTTFilterLen (L790)
	probeRTTInterval = 5 * time.Second        // BBR.ProbeRTTInterval (L802)
	probeRTTDuration = 200 * time.Millisecond // BBR.ProbeRTTDuration (L798)

	// BBR.PacingMarginPercent = 1% (§2.5, L489).
	pacingMargin = 0.99

	// BBR.MaxBwFilterLen: window covers two ProbeBW cycles (§5.5.3,
	// L3500-3502); virtual time is BBR.cycle_count (§5.5.6).
	maxBwFilterLen = roundTripCount(2)
	// BBR.ExtraAckedFilterLen: 10 rounds (§5.5.9, L3770-3771).
	extraAckedFilterLen = roundTripCount(10)

	// Reno coexistence (§5.3.3.8, L2703): T_reno_bound ∈ {62, 63}.
	renoCoexistenceRoundsMax = 63
	// bw_probe_up_rounds cap (§5.3.3.9 RaiseInflightLongtermSlope, L3008).
	bwProbeUpRoundsCap = 30
)

// minPipeCwnd is BBR.MinPipeCwnd (§2.8, L543): 4 * SMSS.
func minPipeCwnd(mss congestion.ByteCount) congestion.ByteCount {
	return 4 * mss
}

type bbr3State int

const (
	stateStartup bbr3State = iota
	stateDrain
	stateProbeBWDown
	stateProbeBWCruise
	stateProbeBWRefill
	stateProbeBWUp
	stateProbeRTT
)

// ackPhase mirrors BBR.ack_phase (§2.11, ACKS_INIT/PROBE_STOPPING/...).
type ackPhase int

const (
	acksInit ackPhase = iota
	acksProbeStarting
	acksProbeFeedback
	acksProbeStopping
)

// rateSample assembles the draft's RS.* fields for one ACK event out of the
// sampler output (see file-comment mapping notes).
type rateSample struct {
	deliveryRate   Bandwidth            // RS.delivery_rate
	rtt            time.Duration        // RS.rtt (infRTT if none)
	isAppLimited   bool                 // RS.is_app_limited
	newlyAcked     congestion.ByteCount // RS.newly_acked
	txInFlight     congestion.ByteCount // RS.tx_in_flight (inflight at send)
	lost           congestion.ByteCount // RS.lost (lost since tx of P)
	delivered      congestion.ByteCount // RS.delivered (acked since tx of P)
	priorDelivered congestion.ByteCount // RS.prior_delivered == P.delivered
	valid          bool                 // whether lastPacketSendState was valid
}

// pendingLoss carries a packet declared lost by the loss-detection timer
// (legacy OnCongestionEvent callback) until the next ACK event folds it
// into the loss model (see OnCongestionEvent).
type pendingLoss struct {
	pn        congestion.PacketNumber
	bytesLost congestion.ByteCount
	state     sendTimeState
}

type bbr3Sender struct {
	rttStats congestion.RTTStatsProvider
	clock    Clock
	pacer    *common.Pacer
	sampler  *bandwidthSampler

	// losses declared by the loss timer, drained on the next ACK event
	pendingLosses []pendingLoss

	state      bbr3State
	pacingGain float64
	cwndGain   float64

	// --- rate model (draft §5.5.2-§5.5.6, §5.5.10.3) ---
	maxBwFilter *WindowedFilter[Bandwidth, roundTripCount]
	cycleCount  roundTripCount
	bwLatest    Bandwidth // 1-round max of delivery rate
	bwShortterm Bandwidth // inf when unset
	bw          Bandwidth // min(max_bw, bw_shortterm) — BoundBWForModel

	// --- volume model (draft §5.5.7-§5.5.9, §5.5.10) ---
	minRtt           time.Duration
	minRttStamp      time.Time
	probeRttMinDelay time.Duration
	probeRttMinStamp time.Time
	probeRttExpired  bool

	inflightLongterm  congestion.ByteCount // inf when unset
	inflightShortterm congestion.ByteCount // inf when unset
	inflightLatest    congestion.ByteCount
	extraAcked        congestion.ByteCount
	extraAckedFilter  *WindowedFilter[congestion.ByteCount, roundTripCount]
	extraAckedStart   time.Time // extra_acked_interval_start
	extraAckedBytes   congestion.ByteCount
	offloadBudget     congestion.ByteCount
	maxInflight       congestion.ByteCount

	// --- round counting (draft §5.5.1) ---
	roundCount         roundTripCount
	roundStart         bool
	nextRoundDelivered congestion.ByteCount
	roundsSinceProbeUp uint64

	// --- full-pipe estimator (draft §5.3.1.2) ---
	fullBw        Bandwidth
	fullBwCount   int64
	fullBwNow     bool
	fullBwReached bool

	// --- congestion signals / loss (draft §5.5.10) ---
	isLossInRound       bool
	lossRoundDelivered  congestion.ByteCount
	lossRoundStart      bool
	bytesLostInRound    congestion.ByteCount
	lossCountInRound    uint64
	maxLossTxInFlight   congestion.ByteCount
	prevProbeTooHigh    bool
	prevProbePrecaution bool
	isBwProbeSample     bool

	// --- ProbeBW cycle (draft §5.3.3.9) ---
	cycleStamp  time.Time
	bwProbeWait time.Duration
	ackPhase    ackPhase

	// longterm inflight growth (draft L2863, L3006-3029)
	probeUpAckedPerInc congestion.ByteCount
	bwProbeUpAcked     congestion.ByteCount
	bwProbeUpRounds    uint64

	// drain entry round (draft §2.7 BBR.drain_start_round, L524)
	drainStartRoundVal roundTripCount

	// --- ProbeRTT (draft §5.3.4.3) ---
	probeRttDoneStamp time.Time
	probeRttRoundDone bool

	idleRestart bool
	priorCwnd   congestion.ByteCount

	// --- control parameters ---
	cwnd        congestion.ByteCount
	pacingRate  Bandwidth
	sendQuantum congestion.ByteCount

	initialCwnd congestion.ByteCount
	minCwnd     congestion.ByteCount
	maxCwnd     congestion.ByteCount
	mss         congestion.ByteCount

	bytesInFlight   congestion.ByteCount // refreshed per sent/event
	sentCwndLimited bool                 // approx of C.is_cwnd_limited
}

var _ congestion.CongestionControl = &bbr3Sender{}

func NewBbr3Sender(clock Clock, initialMaxDatagramSize congestion.ByteCount) *bbr3Sender {
	initialCwnd := initialCongestionWindowPackets * initialMaxDatagramSize
	maxCwnd := congestion.MaxCongestionWindowPackets * initialMaxDatagramSize
	b := &bbr3Sender{
		clock:             clock,
		sampler:           newBandwidthSampler(extraAckedFilterLen),
		maxBwFilter:       NewWindowedFilter(maxBwFilterLen, MaxFilter[Bandwidth]),
		extraAckedFilter:  NewWindowedFilter(extraAckedFilterLen, MaxFilter[congestion.ByteCount]),
		bwShortterm:       infBandwidth,
		inflightLongterm:  infByteCount,
		inflightShortterm: infByteCount,
		// C.cwnd starts at the transport's initial cwnd (draft §5.6.4.1).
		cwnd:               initialCwnd,
		initialCwnd:        initialCwnd,
		minCwnd:            minPipeCwnd(initialMaxDatagramSize),
		maxCwnd:            maxCwnd,
		mss:                initialMaxDatagramSize,
		probeUpAckedPerInc: infByteCount,
		nextRoundDelivered: 0,
	}
	b.pacer = common.NewPacer(b.bandwidthForPacer)

	// OnInit (draft §5.2.1, L2077-2108): min_rtt = C.srtt ? srtt : Infinity,
	// min_rtt_stamp = Now(). The RTT provider is wired in later by
	// SetRTTStatsProvider; until then min_rtt stays unknown (0) and RTT-using
	// helpers fall back gracefully. The stamps MUST be initialized to now:
	// otherwise the zero time.Time (year 1) makes probe_rtt_expired evaluate
	// true on the very first ACK and the flow spuriously enters ProbeRTT.
	now := clock.Now()
	b.minRttStamp = now
	b.probeRttMinStamp = now
	// probe_rtt_min_delay starts unset (+infinity) so the first RTT sample
	// updates it (cf. Linux bbr_reset_min_rtt; the draft's `rtt < delay`
	// condition can never fire on a zero-initialized delay).
	b.probeRttMinDelay = infRTT
	b.extraAckedStart = now
	b.resetShortTermModel()
	b.initRoundCounting()
	b.resetFullBW()
	b.initPacingRate()
	b.enterStartup()
	return b
}

// ByteCount "infinity" helper (draft uses Infinity for unset bounds).
const infByteCount congestion.ByteCount = congestion.ByteCount(^uint64(0) >> 1)

func (b *bbr3Sender) SetRTTStatsProvider(provider congestion.RTTStatsProvider) {
	b.rttStats = provider
}

// ---------------------------------------------------------------- interface

func (b *bbr3Sender) TimeUntilSend(bytesInFlight congestion.ByteCount) time.Time {
	return b.pacer.TimeUntilSend()
}

func (b *bbr3Sender) HasPacingBudget(now time.Time) bool {
	return b.pacer.Budget(now) >= b.mss
}

// OnPacketSent implements per-transmit steps (draft §5.2.2 OnTransmit →
// HandleRestartFromIdle, L2115-2116) plus sampler/pacer bookkeeping.
func (b *bbr3Sender) OnPacketSent(
	sentTime time.Time,
	bytesInFlight congestion.ByteCount,
	packetNumber congestion.PacketNumber,
	bytes congestion.ByteCount,
	isRetransmittable bool,
) {
	b.pacer.SentPacket(sentTime, bytes)
	// The fork's sentPacketHandler adds size to bytesInFlight BEFORE invoking
	// this callback, so the parameter already includes the current packet
	// (matching the sampler's bytes_in_flight semantics). Pre-send in-flight
	// of zero means the connection was quiescent.
	if bytesInFlight == bytes && b.sampler.IsAppLimited() {
		b.handleRestartFromIdle(sentTime)
	}
	if bytesInFlight > b.cwnd {
		b.sentCwndLimited = true
	}
	b.bytesInFlight = bytesInFlight
	b.sampler.OnPacketSent(sentTime, packetNumber, bytes, bytesInFlight, isRetransmittable)
}

func (b *bbr3Sender) CanSend(bytesInFlight congestion.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

func (b *bbr3Sender) MaybeExitSlowStart() {}

func (b *bbr3Sender) OnPacketAcked(number congestion.PacketNumber, ackedBytes, priorInFlight congestion.ByteCount, eventTime time.Time) {
	// All ACK work is done in OnCongestionEventEx (invoked once per ACK).
}

func (b *bbr3Sender) OnCongestionEvent(number congestion.PacketNumber, lostBytes, priorInFlight congestion.ByteCount) {
	// Loss-detection-timer path: the fork's sentPacketHandler invokes this
	// legacy callback for packets declared lost by the loss timer (early
	// retransmit / RACK tail loss), and those packets never reach
	// OnCongestionEventEx (their lostPacketsInfo entries are reset by the
	// next ReceivedAck before it fires Ex). Keep the sampler consistent now
	// and defer the model update (§5.5.10) to the next ACK event. Any ACK
	// drains the queue, so it stays bounded by one loss episode.
	if st := b.sampler.OnPacketLost(number, lostBytes); st.isValid {
		b.pendingLosses = append(b.pendingLosses, pendingLoss{
			pn:        number,
			bytesLost: lostBytes,
			state:     st,
		})
	}
}

func (b *bbr3Sender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	// Dead code in the fork (never invoked); quiche's Bbr3Sender is also empty.
}

func (b *bbr3Sender) SetMaxDatagramSize(s congestion.ByteCount) {
	if s < b.mss {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", b.mss, s))
	}
	cwndIsMin := b.cwnd == b.minCwnd
	b.mss = s
	b.minCwnd = minPipeCwnd(s)
	if cwndIsMin {
		b.cwnd = b.minCwnd
	}
	b.pacer.SetMaxDatagramSize(s)
}

func (b *bbr3Sender) InSlowStart() bool { return b.state == stateStartup }

func (b *bbr3Sender) InRecovery() bool {
	// No loss-recovery hooks in the fork's interface (see package comment).
	return false
}

func (b *bbr3Sender) GetCongestionWindow() congestion.ByteCount { return b.cwnd }

// ------------------------------------------------------------- state machine

func (b *bbr3Sender) enterStartup() {
	// EnterStartup (draft L2198-2201).
	b.state = stateStartup
	b.pacingGain = startupPacingGain
	b.cwndGain = defaultCwndGain
}

func (b *bbr3Sender) enterDrain() {
	// EnterDrain (draft L2341-2345).
	b.state = stateDrain
	b.pacingGain = drainPacingGain
	b.cwndGain = defaultCwndGain
	b.drainStartRoundVal = b.roundCount
}

func (b *bbr3Sender) enterProbeBW() {
	// EnterProbeBW (draft L2840-2842).
	b.cwndGain = defaultCwndGain
	b.startProbeBWDown()
}

func (b *bbr3Sender) startProbeBWDown() {
	// StartProbeBW_DOWN (draft L2861-2868); DOWN pacing gain 0.90 with
	// DefaultCwndGain (§5.3.3.1 L2415, §5.6.1 table L4212-4217).
	b.resetCongestionSignals()
	b.probeUpAckedPerInc = infByteCount
	b.pickProbeWait()
	b.cycleStamp = b.clock.Now()
	b.ackPhase = acksProbeStopping
	b.startRound()
	b.pacingGain = probeDownPacingGain
	b.cwndGain = defaultCwndGain
	b.state = stateProbeBWDown
}

func (b *bbr3Sender) startProbeBWCruise() {
	// StartProbeBW_CRUISE (draft L2870-2871); pacing 1.0 (§5.3.3.2).
	b.pacingGain = 1
	b.cwndGain = defaultCwndGain
	b.state = stateProbeBWCruise
}

func (b *bbr3Sender) startProbeBWRefill() {
	// StartProbeBW_REFILL (draft L2873-2880); pacing 1.0 (§5.3.3.3 L2479).
	b.resetShortTermModel()
	b.bwProbeUpRounds = 0
	b.bwProbeUpAcked = 0
	b.prevProbePrecaution = false
	b.ackPhase = acksProbeStarting
	b.startRound()
	b.pacingGain = 1
	b.cwndGain = defaultCwndGain
	b.state = stateProbeBWRefill
}

func (b *bbr3Sender) startProbeBWUp(rs *rateSample) {
	// StartProbeBW_UP (draft L2882-2888); UP probes with pacing 1.25 and
	// raises cwnd_gain to 2.25 (§5.3.3.5 L2511-2516).
	b.ackPhase = acksProbeStarting
	b.startRound()
	b.resetFullBW()
	if rs != nil && rs.valid && rs.deliveryRate > b.fullBw {
		b.fullBw = rs.deliveryRate
	}
	b.pacingGain = probeUpPacingGain
	b.cwndGain = probeUpCwndGain
	b.state = stateProbeBWUp
	b.raiseInflightLongtermSlope()
}

// updateProbeBWCyclePhase implements UpdateProbeBWCyclePhase (draft
// L2918-2947). Returns true if AdaptLongTermModel already performed a state
// transition.
func (b *bbr3Sender) updateProbeBWCyclePhase(rs *rateSample) bool {
	if !b.fullBwReached {
		return false // only steady-state behavior here
	}
	if b.adaptLongTermModel(rs) {
		return true // already decided state transition
	}
	if !b.isInAProbeBWState() {
		return false
	}
	switch b.state {
	case stateProbeBWDown:
		if b.isTimeToProbeBW() {
			return true // already transitioned to REFILL
		}
		if b.isTimeToCruise() {
			b.startProbeBWCruise()
		}
	case stateProbeBWCruise:
		if b.isTimeToProbeBW() {
			return true // transitioned to REFILL
		}
	case stateProbeBWRefill:
		// After one round of REFILL, start UP (draft L2938-2942).
		if b.roundStart {
			b.isBwProbeSample = true
			b.startProbeBWUp(rs)
		}
	case stateProbeBWUp:
		if b.isTimeToGoDown(rs) {
			b.prevProbeTooHigh = false // no high loss (yet)
			b.startProbeBWDown()
		}
	}
	return false
}

func (b *bbr3Sender) isInAProbeBWState() bool {
	// IsInAProbeBWState (draft L2951-2956).
	switch b.state {
	case stateProbeBWDown, stateProbeBWCruise, stateProbeBWRefill, stateProbeBWUp:
		return true
	}
	return false
}

func (b *bbr3Sender) isProbingBW() bool {
	// IsProbingBW (draft L2986-2989).
	return b.state == stateStartup || b.state == stateProbeBWRefill || b.state == stateProbeBWUp
}

// isTimeToCruise implements IsTimeToCruise (draft L2959-2964).
func (b *bbr3Sender) isTimeToCruise() bool {
	if b.bytesInFlight > b.inflightWithHeadroom() {
		return false // not enough headroom
	}
	if b.bytesInFlight > b.inflightAtBW(b.maxBw(), 1.0) {
		return false // inflight > estimated BDP
	}
	return true
}

// isTimeToGoDown implements IsTimeToGoDown (draft L2974-2984).
func (b *bbr3Sender) isTimeToGoDown(rs *rateSample) bool {
	// Precautionary Bandwidth Probing: Deceleration (draft L2975-2978).
	if b.prevProbeTooHigh && b.bytesInFlight >= b.inflightLongterm {
		b.prevProbePrecaution = true
		return true
	}
	if b.sentCwndLimited && b.cwnd >= b.inflightLongterm {
		// bw is limited by inflight_longterm: reset full-pipe estimator.
		b.resetFullBW()
		if rs != nil && rs.valid {
			b.fullBw = rs.deliveryRate
		}
	} else if b.fullBwNow {
		return true // fully used path bw
	}
	return false
}

// isTimeToProbeBW implements IsTimeToProbeBW (draft L2806-2811).
func (b *bbr3Sender) isTimeToProbeBW() bool {
	if b.hasElapsedInPhase(b.bwProbeWait) || b.isRenoCoexistenceProbeTime() {
		b.startProbeBWRefill()
		return true
	}
	return false
}

// pickProbeWait implements PickProbeWait (draft L2816-2822).
func (b *bbr3Sender) pickProbeWait() {
	b.roundsSinceProbeUp = uint64(rand.Int31n(2)) // 0 or 1
	b.bwProbeWait = 2*time.Second + time.Duration(rand.Int31n(1000))*time.Millisecond
}

// isRenoCoexistenceProbeTime implements IsRenoCoexistenceProbeTime (draft
// L2824-2827). TargetInflight is measured in packets (cf. Linux bbr).
func (b *bbr3Sender) isRenoCoexistenceProbeTime() bool {
	rounds := b.targetInflight() / b.mss
	if rounds > renoCoexistenceRoundsMax {
		rounds = renoCoexistenceRoundsMax
	}
	return b.roundsSinceProbeUp >= uint64(rounds)
}

// targetInflight implements TargetInflight (draft L2831-2832).
func (b *bbr3Sender) targetInflight() congestion.ByteCount {
	return minByteCount2(b.bdp(), b.cwnd)
}

func (b *bbr3Sender) hasElapsedInPhase(interval time.Duration) bool {
	// HasElapsedInPhase (draft L2991-2992).
	return b.clock.Now().After(b.cycleStamp.Add(interval))
}

// inflightWithHeadroom implements InflightWithHeadroom (draft L2998-3003).
func (b *bbr3Sender) inflightWithHeadroom() congestion.ByteCount {
	if b.inflightLongterm == infByteCount {
		return infByteCount
	}
	hr := congestion.ByteCount(headroom * float64(b.inflightLongterm))
	if hr < b.mss {
		hr = b.mss
	}
	return maxByteCount2(b.inflightLongterm-hr, b.minCwnd)
}

// raiseInflightLongtermSlope implements RaiseInflightLongtermSlope (draft
// L3006-3009).
func (b *bbr3Sender) raiseInflightLongtermSlope() {
	growthThisRound := uint64(1) << b.bwProbeUpRounds
	if b.bwProbeUpRounds < bwProbeUpRoundsCap {
		b.bwProbeUpRounds++
	}
	inc := b.cwnd / congestion.ByteCount(growthThisRound)
	b.probeUpAckedPerInc = maxByteCount2(inc, b.mss)
}

// probeInflightLongtermUpward implements ProbeInflightLongtermUpward (draft
// L3012-3029).
func (b *bbr3Sender) probeInflightLongtermUpward(rs *rateSample) {
	if !b.sentCwndLimited || b.cwnd < b.inflightLongterm {
		return // not fully using inflight_longterm, so don't grow it
	}
	b.bwProbeUpAcked += rs.newlyAcked
	if b.bwProbeUpAcked >= b.probeUpAckedPerInc && b.probeUpAckedPerInc > 0 {
		delta := b.bwProbeUpAcked / b.probeUpAckedPerInc
		b.bwProbeUpAcked -= delta * b.probeUpAckedPerInc
		b.inflightLongterm += delta * b.mss
	}
	if b.roundStart {
		b.raiseInflightLongtermSlope()
	}
}

// adaptLongTermModel implements AdaptLongTermModel (draft L3034-3059).
// Returns true if it decided a state transition.
func (b *bbr3Sender) adaptLongTermModel(rs *rateSample) bool {
	if b.ackPhase == acksProbeStarting && b.roundStart {
		// starting to get bw probing samples
		b.ackPhase = acksProbeFeedback
	}
	if b.ackPhase == acksProbeStopping && b.roundStart {
		// end of samples from bw probing phase
		b.isBwProbeSample = false
		b.ackPhase = acksInit
		if b.isInAProbeBWState() && rs != nil && rs.valid && !rs.isAppLimited {
			b.advanceMaxBwFilter()
		}
		// Precautionary Bandwidth Probing: Acceleration (draft L3044-3049).
		if b.isInAProbeBWState() && b.prevProbePrecaution && !b.prevProbeTooHigh {
			b.startProbeBWRefill()
			return true
		}
	}
	if !b.isInflightTooHigh(rs) {
		// Loss rate is safe: adjust upper bounds upward.
		if b.inflightLongterm == infByteCount {
			return false // no upper bounds to raise
		}
		if rs != nil && rs.valid && rs.txInFlight > b.inflightLongterm {
			b.inflightLongterm = rs.txInFlight
		}
		if b.state == stateProbeBWUp && rs != nil && rs.valid {
			b.probeInflightLongtermUpward(rs)
		}
	}
	return false
}

// ----------------------------------------------------------------- ACK path

// OnCongestionEventEx implements UpdateOnACK (draft §5.2.3, L2133-2154).
func (b *bbr3Sender) OnCongestionEventEx(
	priorInFlight congestion.ByteCount,
	eventTime time.Time,
	ackedPackets []congestion.AckedPacketInfo,
	lostPackets []congestion.LostPacketInfo,
) {
	totalAckedBefore := b.sampler.TotalBytesAcked()
	b.maybeAppLimited(priorInFlight)

	// Drain losses queued by the loss-detection-timer path (see
	// OnCongestionEvent) before processing this event, so per-round loss
	// accounting (§5.5.10) sees them in chronological order.
	if len(b.pendingLosses) != 0 {
		pending := b.pendingLosses
		b.pendingLosses = nil
		lostInfos := make([]congestion.LostPacketInfo, 0, len(pending))
		states := make([]sendTimeState, 0, len(pending))
		for _, p := range pending {
			lostInfos = append(lostInfos, congestion.LostPacketInfo{
				PacketNumber: p.pn,
				BytesLost:    p.bytesLost,
			})
			states = append(states, p.state)
		}
		b.handleLostPackets(lostInfos, states)
	}

	// Refresh local inflight (same accounting as v1).
	b.bytesInFlight = priorInFlight
	for _, p := range ackedPackets {
		b.bytesInFlight -= p.BytesAcked
	}
	for _, p := range lostPackets {
		b.bytesInFlight -= p.BytesLost
	}
	b.sentCwndLimited = false

	// GenerateRateSample (§4.1 / §5.2.3): the sampler produces the max
	// bandwidth sample, min RTT sample and send-time states for this event.
	sample := b.sampler.OnCongestionEvent(eventTime, ackedPackets, lostPackets, b.maxBw(), infBandwidth, b.roundCount)

	rs := &rateSample{rtt: infRTT}
	rs.newlyAcked = b.sampler.TotalBytesAcked() - totalAckedBefore
	if sample.lastPacketSendState.isValid {
		rs.valid = true
		rs.deliveryRate = sample.sampleMaxBandwidth
		rs.rtt = sample.sampleRtt
		rs.isAppLimited = sample.lastPacketSendState.isAppLimited
		rs.txInFlight = sample.lastPacketSendState.bytesInFlight
		rs.lost = b.sampler.TotalBytesLost() - sample.lastPacketSendState.totalBytesLost
		rs.delivered = b.sampler.TotalBytesAcked() - sample.lastPacketSendState.totalBytesAcked
		rs.priorDelivered = sample.lastPacketSendState.totalBytesAcked
	}

	// Per-loss steps (draft §5.2.4 / §5.5.10.2 HandleLostPacket).
	b.handleLostPackets(lostPackets, sample.lostSendStates)

	// UpdateModelAndState (draft L2138-2149), in draft order.
	b.updateLatestDeliverySignals(rs)
	b.updateCongestionSignals(rs)
	b.updateACKAggregation(rs)
	b.checkFullBWReached(rs)
	b.checkStartupDone(rs)
	b.checkDrainDone()
	b.updateProbeBWCyclePhase(rs)
	b.updateMinRTT(rs)
	b.checkProbeRTT(rs)
	b.advanceLatestDeliverySignals(rs)
	b.boundBWForModel()

	// UpdateControlParameters (draft L2151-2154).
	b.setPacingRate()
	b.setSendQuantum()
	b.setCwnd(rs)

	// Sampler cleanup, same least-unacked estimate as v1 (fast retransmit
	// bounds the error by packetThreshold).
	var leastUnacked congestion.PacketNumber
	if len(ackedPackets) != 0 {
		leastUnacked = ackedPackets[len(ackedPackets)-1].PacketNumber - 2
	} else if len(lostPackets) != 0 {
		leastUnacked = lostPackets[len(lostPackets)-1].PacketNumber + 1
	} else {
		leastUnacked = b.sampler.lastSentPacket + 1
	}
	b.sampler.RemoveObsoletePackets(leastUnacked)
}

// handleLostPackets implements NoteLoss + HandleLostPacket (draft
// L3932-3947) for the packets declared lost in this ACK event.
func (b *bbr3Sender) handleLostPackets(lostPackets []congestion.LostPacketInfo, lostSendStates []sendTimeState) {
	if len(lostPackets) == 0 {
		return
	}
	// NoteLoss (draft L3932-3936).
	if !b.isLossInRound {
		b.lossRoundDelivered = b.sampler.TotalBytesAcked()
		// SaveStateUponLoss (§5.5.11.1) would go here; undo is not
		// supported (no spurious-recovery hook in the transport).
	}
	b.isLossInRound = true
	// Track per-round loss volume/events for CheckStartupHighLoss (§5.3.1.3);
	// each lost QUIC packet number counts as one loss event/range.
	for _, p := range lostPackets {
		b.bytesLostInRound += p.BytesLost
	}
	b.lossCountInRound += uint64(len(lostPackets))

	totalLostNow := b.sampler.TotalBytesLost()
	// Scan every lost packet's send-time in-flight for the startup
	// high-loss denominator (§5.3.1.3), independent of the probe-reaction
	// loop below (which stops at the first reaction in non-probing states).
	for i := range lostSendStates {
		if st := &lostSendStates[i]; st.bytesInFlight > b.maxLossTxInFlight {
			b.maxLossTxInFlight = st.bytesInFlight
		}
	}
	for i := range lostSendStates {
		st := &lostSendStates[i]
		if !b.isBwProbeSample {
			break // not a packet sent while probing bandwidth
		}
		rs := &rateSample{
			txInFlight:   st.bytesInFlight,
			lost:         totalLostNow - st.totalBytesLost,
			isAppLimited: st.isAppLimited,
			valid:        true,
		}
		if !b.isInflightTooHigh(rs) {
			continue
		}
		rs.txInFlight = b.inflightAtLoss(st, rs)
		b.handleInflightTooHigh(rs)
		break // only react once per bw probe (is_bw_probe_sample=false)
	}
}

// isInflightTooHigh implements IsInflightTooHigh (draft L3872-3874).
// QUIC ACK ranges are selective, so the !has_selective_acks clause never
// applies.
func (b *bbr3Sender) isInflightTooHigh(rs *rateSample) bool {
	return rs.txInFlight > 0 && float64(rs.lost) > float64(rs.txInFlight)*lossThresh
}

// handleInflightTooHigh implements HandleInflightTooHigh (draft L3876-3884).
func (b *bbr3Sender) handleInflightTooHigh(rs *rateSample) {
	b.prevProbeTooHigh = true
	b.isBwProbeSample = false // only react once per bw probe
	if !rs.isAppLimited {
		b.inflightLongterm = maxByteCount2(rs.txInFlight,
			congestion.ByteCount(beta*float64(b.targetInflight())))
	}
	if b.state == stateProbeBWUp {
		// undo_state bookkeeping skipped (no spurious-recovery hook).
		b.startProbeBWDown()
	}
}

// inflightAtLoss implements InflightAtLoss (draft L3954-3964): estimate at
// what prefix of lost packet P the loss rate crossed BBR.LossThresh.
func (b *bbr3Sender) inflightAtLoss(st *sendTimeState, rs *rateSample) congestion.ByteCount {
	inflightPrev := rs.txInFlight - st.size
	lostPrev := rs.lost - st.size
	lostPrefix := (lossThresh*float64(inflightPrev) - float64(lostPrev)) / (1 - lossThresh)
	if lostPrefix < 0 {
		lostPrefix = 0
	}
	return inflightPrev + congestion.ByteCount(lostPrefix)
}

// updateLatestDeliverySignals implements UpdateLatestDeliverySignals (draft
// L4017-4023).
func (b *bbr3Sender) updateLatestDeliverySignals(rs *rateSample) {
	b.lossRoundStart = false
	if rs.valid {
		if rs.deliveryRate > b.bwLatest {
			b.bwLatest = rs.deliveryRate
		}
		if rs.delivered > b.inflightLatest {
			b.inflightLatest = rs.delivered
		}
	}
	if rs.valid && rs.priorDelivered >= b.lossRoundDelivered {
		b.lossRoundDelivered = b.sampler.TotalBytesAcked()
		b.lossRoundStart = true
	}
}

// advanceLatestDeliverySignals implements AdvanceLatestDeliverySignals
// (draft L4026-4037).
func (b *bbr3Sender) advanceLatestDeliverySignals(rs *rateSample) {
	if !b.lossRoundStart {
		return
	}
	if rs.valid {
		b.bwLatest = rs.deliveryRate
		b.inflightLatest = rs.delivered
	}
}

// resetCongestionSignals implements ResetCongestionSignals (draft L4039-4042).
func (b *bbr3Sender) resetCongestionSignals() {
	b.isLossInRound = false
	b.bwLatest = 0
	b.inflightLatest = 0
	b.bytesLostInRound = 0
	b.lossCountInRound = 0
	b.maxLossTxInFlight = 0
}

// updateCongestionSignals implements UpdateCongestionSignals (draft
// L4045-4050).
func (b *bbr3Sender) updateCongestionSignals(rs *rateSample) {
	b.updateMaxBw(rs)
	if !b.lossRoundStart {
		return // wait until end of round trip
	}
	// The round that absorbed the losses just ended: evaluate
	// CheckStartupHighLoss (§5.3.1.3) while is_loss_in_round and the live
	// per-round counters are still set (the draft clears is_loss_in_round
	// below; Linux evaluates inside the same function).
	b.checkStartupHighLoss()
	b.adaptLowerBoundsFromCongestion()
	b.isLossInRound = false
	b.bytesLostInRound = 0
	b.lossCountInRound = 0
	b.maxLossTxInFlight = 0
}

// adaptLowerBoundsFromCongestion implements AdaptLowerBoundsFromCongestion
// (draft L4053-4058).
func (b *bbr3Sender) adaptLowerBoundsFromCongestion() {
	if b.isProbingBW() {
		return
	}
	if b.isLossInRound {
		b.initLowerBounds()
		b.lossLowerBounds()
	}
}

// initLowerBounds implements InitLowerBounds (draft L4061-4065).
func (b *bbr3Sender) initLowerBounds() {
	if b.bwShortterm == infBandwidth {
		b.bwShortterm = b.maxBw()
	}
	if b.inflightShortterm == infByteCount {
		b.inflightShortterm = b.cwnd
	}
}

// lossLowerBounds implements LossLowerBounds (draft L4068-4072).
func (b *bbr3Sender) lossLowerBounds() {
	b.bwShortterm = maxBandwidth2(b.bwLatest, Bandwidth(beta*float64(b.bwShortterm)))
	b.inflightShortterm = maxByteCount2(b.inflightLatest,
		congestion.ByteCount(beta*float64(b.inflightShortterm)))
}

// resetShortTermModel implements ResetShortTermModel (draft L4074-4076).
func (b *bbr3Sender) resetShortTermModel() {
	b.bwShortterm = infBandwidth
	b.inflightShortterm = infByteCount
}

// boundBWForModel implements BoundBWForModel (draft L4078-4079).
func (b *bbr3Sender) boundBWForModel() {
	b.bw = minBandwidth2(b.maxBw(), b.bwShortterm)
}

// updateACKAggregation implements UpdateACKAggregation (draft L3813-3834).
func (b *bbr3Sender) updateACKAggregation(rs *rateSample) {
	if !rs.valid {
		return
	}
	interval := b.clock.Now().Sub(b.extraAckedStart)
	expectedDelivered := bytesFromBandwidthAndTimeDelta(b.bw, interval)
	// Reset interval if ACK rate is below expected rate (draft L3817-3821).
	if b.extraAckedBytes <= expectedDelivered {
		b.extraAckedBytes = 0
		b.extraAckedStart = b.clock.Now()
		expectedDelivered = 0
	}
	b.extraAckedBytes += rs.newlyAcked
	extra := b.extraAckedBytes - expectedDelivered
	if extra > b.cwnd {
		extra = b.cwnd
	}
	filterLen := extraAckedFilterLen
	if !b.fullBwReached {
		filterLen = 1 // in Startup, just remember 1 round
	}
	b.extraAckedFilter.SetWindowLength(filterLen)
	b.extraAckedFilter.Update(extra, b.roundCount)
	b.extraAcked = b.extraAckedFilter.GetBest()
}

// ------------------------------------------------------- full-pipe estimator

// resetFullBW implements ResetFullBW (draft L2256-2259).
func (b *bbr3Sender) resetFullBW() {
	b.fullBw = 0
	b.fullBwCount = 0
	b.fullBwNow = false
}

// checkFullBWReached implements CheckFullBWReached (draft L2266-2276).
func (b *bbr3Sender) checkFullBWReached(rs *rateSample) {
	if b.fullBwNow || !b.roundStart || !rs.valid || rs.isAppLimited {
		return
	}
	if rs.deliveryRate >= Bandwidth(1.25*float64(b.fullBw)) {
		b.resetFullBW() // bw is still growing, so reset
		b.fullBw = rs.deliveryRate
		return
	}
	b.fullBwCount++
	b.fullBwNow = b.fullBwCount >= 3
	if b.fullBwNow {
		b.fullBwReached = true
	}
}

// checkStartupDone implements CheckStartupDone (draft L2216-2219). The
// high-loss evaluation itself runs inside updateCongestionSignals (see
// checkStartupHighLoss) so it sees is_loss_in_round before the per-round
// reset; here we only perform the transition.
func (b *bbr3Sender) checkStartupDone(rs *rateSample) {
	if b.state == stateStartup && b.fullBwReached {
		b.enterDrain()
	}
}

// checkStartupHighLoss implements CheckStartupHighLoss (draft §5.3.1.3,
// L2284-2323). The draft requires one full round in fast recovery; the fork's
// interface provides no recovery-state signal, so "a round trip has elapsed
// since the first loss of the episode" (loss_round_start) is used as the
// proxy. Loss rate is measured over the round; ≥6 losses must be observed in
// that round (BBRStartupFullLossCnt).
func (b *bbr3Sender) checkStartupHighLoss() {
	if b.state != stateStartup || !b.isLossInRound || !b.lossRoundStart {
		return
	}
	if b.lossCountInRound < startupFullLossCount {
		return
	}
	if b.maxLossTxInFlight == 0 ||
		float64(b.bytesLostInRound) <= float64(b.maxLossTxInFlight)*lossThresh {
		return
	}
	b.fullBwReached = true
	b.inflightLongterm = maxByteCount2(b.bdp(), b.inflightLatest)
}

// checkDrainDone implements CheckDrainDone (draft L2368-2372). Inflight()
// uses the bounded BBR.bw, not the raw max_bw filter value.
func (b *bbr3Sender) checkDrainDone() {
	if b.state == stateDrain &&
		(b.bytesInFlight <= b.inflightAtBW(b.bw, 1.0) ||
			b.roundCount > b.drainStartRoundVal+3) {
		b.enterProbeBW()
	}
}

// ------------------------------------------------------------ ProbeRTT etc.

// updateMinRTT implements UpdateMinRTT (draft L3197-3211).
func (b *bbr3Sender) updateMinRTT(rs *rateSample) {
	now := b.clock.Now()
	b.probeRttExpired = now.After(b.probeRttMinStamp.Add(probeRTTInterval))
	if rs.rtt != infRTT && (rs.rtt < b.probeRttMinDelay || b.probeRttExpired) {
		b.probeRttMinDelay = rs.rtt
		b.probeRttMinStamp = now
	}
	minRttExpired := now.After(b.minRttStamp.Add(minRTTFilterLen))
	// Guard against copying the infRTT sentinel: a loss-only event yields
	// rs.valid with rs.rtt == infRTT (no RTT sample), and copying that into
	// min_rtt would poison BDP estimates until the next real sample.
	if b.probeRttMinDelay != infRTT &&
		(b.probeRttMinDelay < b.minRtt || b.minRtt == 0 || minRttExpired) {
		b.minRtt = b.probeRttMinDelay
		b.minRttStamp = b.probeRttMinStamp
	}
}

// checkProbeRTT implements CheckProbeRTT (draft L3253-3265).
func (b *bbr3Sender) checkProbeRTT(rs *rateSample) {
	now := b.clock.Now()
	if b.state != stateProbeRTT && b.probeRttExpired && !b.idleRestart {
		b.enterProbeRTT()
		b.saveCwnd()
		b.probeRttDoneStamp = time.Time{}
		b.ackPhase = acksProbeStopping
		b.startRound()
	}
	if b.state == stateProbeRTT {
		b.handleProbeRTT(now)
	}
	// draft L3264-3265: only delivered data ends the idle-restart window.
	if rs.valid && rs.delivered > 0 {
		b.idleRestart = false
	}
}

func (b *bbr3Sender) enterProbeRTT() {
	// EnterProbeRTT (draft L3267-3270).
	b.state = stateProbeRTT
	b.pacingGain = 1
	b.cwndGain = probeRTTCwndGain
}

// handleProbeRTT implements HandleProbeRTT (draft L3272-3287).
func (b *bbr3Sender) handleProbeRTT(now time.Time) {
	// Ignore low rate samples during ProbeRTT (MarkConnectionAppLimited).
	b.sampler.OnAppLimited()
	if b.probeRttDoneStamp.IsZero() && b.bytesInFlight <= b.probeRTTCwnd() {
		// Wait for at least ProbeRTTDuration to elapse (draft L3277-3279).
		b.probeRttDoneStamp = now.Add(probeRTTDuration)
		// Wait for at least one round to elapse.
		b.probeRttRoundDone = false
		b.startRound()
	} else if !b.probeRttDoneStamp.IsZero() {
		if b.roundStart {
			b.probeRttRoundDone = true
		}
		if b.probeRttRoundDone {
			b.checkProbeRTTDone(now)
		}
	}
}

// checkProbeRTTDone implements CheckProbeRTTDone (draft L3289-3295).
func (b *bbr3Sender) checkProbeRTTDone(now time.Time) {
	if !b.probeRttDoneStamp.IsZero() && now.After(b.probeRttDoneStamp) {
		// schedule next ProbeRTT:
		b.probeRttMinStamp = now
		b.restoreCwnd()
		b.exitProbeRTT()
	}
}

// exitProbeRTT implements ExitProbeRTT (draft L3322-3328).
func (b *bbr3Sender) exitProbeRTT() {
	b.resetShortTermModel()
	if b.fullBwReached {
		b.startProbeBWDown()
		b.startProbeBWCruise()
	} else {
		b.enterStartup()
	}
}

// handleRestartFromIdle implements HandleRestartFromIdle (draft L3365-3372).
func (b *bbr3Sender) handleRestartFromIdle(now time.Time) {
	b.idleRestart = true
	b.extraAckedStart = now
	if b.isInAProbeBWState() {
		b.setPacingRateWithGain(1)
	} else if b.state == stateProbeRTT {
		b.checkProbeRTTDone(now)
	}
}

// maybeAppLimited marks the sampler app-limited when the connection had
// spare cwnd (same heuristic as the v1 package; stands in for the draft's
// transport-provided C.app_limited signal).
// maybeAppLimited approximates the draft's C.app_limited signal, which the
// fork's interface does not carry. A bare cwnd test (as v1 used) over-marks in
// steady state: pacing deliberately holds about one BDP in flight while cwnd
// allows cwnd_gain×BDP, so every ProbeBW event would be flagged app-limited
// and the bandwidth model would starve of rising samples. Judge instead
// against what the current pacing rate would sustain, capped by cwnd, with
// 3/4 slack (cf. the pacing-aware heuristic in the olicesx fork's bbr3).
func (b *bbr3Sender) maybeAppLimited(bytesInFlight congestion.ByteCount) {
	rtt := b.minRtt
	if rtt <= 0 {
		rtt = b.rttStats.SmoothedRTT()
	}
	if rtt <= 0 {
		// No RTT information yet; do not mark (keeps early samples usable).
		return
	}
	pacingInFlight := congestion.ByteCount(uint64(b.bandwidthForPacer()) * uint64(rtt) / uint64(time.Second))
	limit := minByteCount2(b.cwnd, pacingInFlight)
	if bytesInFlight >= limit*3/4 {
		return
	}
	b.sampler.OnAppLimited()
}

// ------------------------------------------------------------ rate counting

// initRoundCounting implements InitRoundCounting (draft L3429-3432).
func (b *bbr3Sender) initRoundCounting() {
	b.nextRoundDelivered = 0
	b.roundStart = false
	b.roundCount = 0
}

// startRound implements StartRound (draft L3459-3460).
func (b *bbr3Sender) startRound() {
	b.nextRoundDelivered = b.sampler.TotalBytesAcked()
}

// updateRound implements UpdateRound (draft L3450-3457). Returns true when a
// new packet-timed round trip started. P.delivered for the most recently
// ACKed packet is its send-time totalBytesAcked snapshot.
func (b *bbr3Sender) updateRound(rs *rateSample) bool {
	if rs.valid && rs.priorDelivered >= b.nextRoundDelivered {
		b.startRound()
		b.roundCount++
		b.roundsSinceProbeUp++
		b.roundStart = true
		return true
	}
	b.roundStart = false
	return false
}

// updateMaxBw implements UpdateMaxBw (draft L3564-3572).
func (b *bbr3Sender) updateMaxBw(rs *rateSample) {
	b.updateRound(rs)
	if rs.valid && rs.deliveryRate > 0 &&
		(rs.deliveryRate >= b.maxBw() || !rs.isAppLimited) {
		b.maxBwFilter.Update(rs.deliveryRate, b.cycleCount)
	}
}

// advanceMaxBwFilter implements AdvanceMaxBwFilter (draft L3602-3603).
func (b *bbr3Sender) advanceMaxBwFilter() {
	b.cycleCount++
}

func (b *bbr3Sender) maxBw() Bandwidth { return b.maxBwFilter.GetBest() }

// ------------------------------------------------------------ control params

// initPacingRate implements InitPacingRate (draft L4276-4278). The RTT
// provider may not be wired yet at construction; in that case the initial
// rate is derived lazily on first use (see ensureInitialPacingRate).
func (b *bbr3Sender) initPacingRate() {
	if b.rttStats == nil {
		return
	}
	b.ensureInitialPacingRate()
}

func (b *bbr3Sender) ensureInitialPacingRate() {
	if b.pacingRate != 0 || b.rttStats == nil {
		return
	}
	srtt := b.rttStats.SmoothedRTT()
	if srtt <= 0 {
		return
	}
	nominal := BandwidthFromDelta(b.initialCwnd, srtt)
	b.pacingRate = Bandwidth(startupPacingGain * float64(nominal))
}

// setPacingRateWithGain implements SetPacingRateWithGain (draft L4291-4294).
func (b *bbr3Sender) setPacingRateWithGain(gain float64) {
	b.ensureInitialPacingRate()
	rate := Bandwidth(gain * float64(b.bw) * pacingMargin)
	if b.fullBwReached || rate > b.pacingRate {
		if rate > 0 {
			b.pacingRate = rate
		}
	}
}

// setPacingRate implements SetPacingRate (draft L4296-4297).
func (b *bbr3Sender) setPacingRate() {
	b.setPacingRateWithGain(b.pacingGain)
}

// setSendQuantum implements SetSendQuantum (draft L4341-4344).
func (b *bbr3Sender) setSendQuantum() {
	q := bytesFromBandwidthAndTimeDelta(b.pacingRate, time.Millisecond)
	if q > 64*1024 {
		q = 64 * 1024
	}
	b.sendQuantum = maxByteCount2(q, 2*b.mss)
}

// bdp implements BDPMultiple's BBR.bdp computation (draft L4429-4433).
func (b *bbr3Sender) bdp() congestion.ByteCount {
	if b.minRtt == 0 {
		return b.initialCwnd // no valid RTT sample yet
	}
	return congestion.ByteCount(float64(b.bw) / 8 * (float64(b.minRtt) / float64(time.Second)))
}

// bdpMultiple implements BDPMultiple (draft L4429-4433).
func (b *bbr3Sender) bdpMultiple(gain float64) congestion.ByteCount {
	if b.minRtt == 0 {
		return b.initialCwnd
	}
	return congestion.ByteCount(gain * float64(b.bdp()))
}

// quantizationBudget implements QuantizationBudget (draft L4435-4441).
func (b *bbr3Sender) quantizationBudget(inflightCap congestion.ByteCount) congestion.ByteCount {
	// UpdateOffloadBudget for QUIC (§5.5.8.2, L3738-3739).
	b.offloadBudget = b.sendQuantum
	if inflightCap < b.offloadBudget {
		inflightCap = b.offloadBudget
	}
	if inflightCap < b.minCwnd {
		inflightCap = b.minCwnd
	}
	if b.state == stateProbeBWUp {
		inflightCap += 2 * b.mss
	}
	return inflightCap
}

// inflightAtBW implements Inflight(gain) for an explicit bandwidth estimate
// (draft L4443-4445; the two-argument form used by IsTimeToCruise/ProbeRTT).
func (b *bbr3Sender) inflightAtBW(bw Bandwidth, gain float64) congestion.ByteCount {
	if b.minRtt == 0 {
		return b.quantizationBudget(b.initialCwnd)
	}
	bdp := congestion.ByteCount(float64(bw) / 8 * (float64(b.minRtt) / float64(time.Second)))
	return b.quantizationBudget(congestion.ByteCount(gain * float64(bdp)))
}

// updateMaxInflight implements UpdateMaxInflight (draft L4447-4450).
func (b *bbr3Sender) updateMaxInflight() {
	cap := b.bdpMultiple(b.cwndGain)
	cap += b.extraAcked
	b.maxInflight = b.quantizationBudget(cap)
}

// setCwnd implements SetCwnd (draft L4597-4605).
func (b *bbr3Sender) setCwnd(rs *rateSample) {
	b.updateMaxInflight()
	if b.fullBwReached {
		cwnd := b.cwnd + rs.newlyAcked
		if cwnd > b.maxInflight {
			cwnd = b.maxInflight
		}
		b.cwnd = cwnd
	} else if b.cwnd < b.maxInflight || b.sampler.TotalBytesAcked() < b.initialCwnd {
		b.cwnd += rs.newlyAcked
	}
	if b.cwnd < b.minCwnd {
		b.cwnd = b.minCwnd
	}
	b.boundCwndForProbeRTT()
	b.boundCwndForModel()
	if b.cwnd > b.maxCwnd {
		b.cwnd = b.maxCwnd
	}
}

// saveCwnd implements SaveCwnd (draft L4541-4545). Loss-recovery modulation
// is not applicable (InRecovery() is always false in this integration).
func (b *bbr3Sender) saveCwnd() {
	if b.state != stateProbeRTT {
		b.priorCwnd = b.cwnd
	} else {
		b.priorCwnd = maxByteCount2(b.priorCwnd, b.cwnd)
	}
}

// restoreCwnd implements RestoreCwnd (draft L4547-4548).
func (b *bbr3Sender) restoreCwnd() {
	b.cwnd = maxByteCount2(b.cwnd, b.priorCwnd)
}

// probeRTTCwnd implements ProbeRTTCwnd (draft L4559-4562).
// probeRTTCwnd implements ProbeRTTCwnd (draft L4559-4562). BDPMultiple uses
// the bounded BBR.bw, not the raw max_bw filter value.
func (b *bbr3Sender) probeRTTCwnd() congestion.ByteCount {
	c := b.inflightAtBW(b.bw, probeRTTCwndGain)
	return maxByteCount2(c, b.minCwnd)
}

// boundCwndForProbeRTT implements BoundCwndForProbeRTT (draft L4564-4566).
func (b *bbr3Sender) boundCwndForProbeRTT() {
	if b.state == stateProbeRTT {
		c := b.probeRTTCwnd()
		if b.cwnd > c {
			b.cwnd = c
		}
	}
}

// boundCwndForModel implements BoundCwndForModel (draft L4627-4639).
func (b *bbr3Sender) boundCwndForModel() {
	cap := infByteCount
	if b.isInAProbeBWState() && b.state != stateProbeBWCruise {
		cap = b.inflightLongterm
	} else if b.state == stateProbeRTT || b.state == stateProbeBWCruise {
		cap = b.inflightWithHeadroom()
	}
	cap = minByteCount2(cap, b.inflightShortterm)
	cap = maxByteCount2(cap, b.minCwnd)
	if b.cwnd > cap {
		b.cwnd = cap
	}
}

// -------------------------------------------------------------------- pacer

// bandwidthForPacer feeds the token-bucket pacer with the current pacing
// rate in bytes/s. Unlike the v1 package (which uses bw*cwndGain), this uses
// the pacing rate directly — BBRv3 modulates pacing_gain per phase, so the
// pacer must track C.pacing_rate itself (§5.6.2).
func (b *bbr3Sender) bandwidthForPacer() congestion.ByteCount {
	b.ensureInitialPacingRate()
	bps := congestion.ByteCount(float64(b.pacingRate) / float64(BytesPerSecond))
	if bps < minBps {
		// Never return zero: HasPacingBudget=false with TimeUntilSend in the
		// past would wedge the quic-go send loop (same guard as v1).
		return minBps
	}
	return bps
}

// ------------------------------------------------------------------- helpers

func minByteCount2(a, b congestion.ByteCount) congestion.ByteCount {
	if a < b {
		return a
	}
	return b
}

func maxByteCount2(a, b congestion.ByteCount) congestion.ByteCount {
	if a > b {
		return a
	}
	return b
}

func minBandwidth2(a, b Bandwidth) Bandwidth {
	if a < b {
		return a
	}
	return b
}

func maxBandwidth2(a, b Bandwidth) Bandwidth {
	if a > b {
		return a
	}
	return b
}

// GetInitialPacketSize mirrors the v1 helper.
func GetInitialPacketSize(addr net.Addr) congestion.ByteCount {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if udpAddr.IP.To4() != nil {
			return congestion.InitialPacketSizeIPv4
		}
		return congestion.InitialPacketSizeIPv6
	}
	return congestion.MinInitialPacketSize
}
