package brutal

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/daeuniverse/outbound/protocol/tuic/congestion/common"

	"github.com/daeuniverse/quic-go/congestion"
)

const (
	pktInfoSlotCount           = 5 // slot index is based on seconds, so this is basically how many seconds we sample
	minSampleCount             = 50
	minAckRate                 = 0.8
	congestionWindowMultiplier = 2

	debugEnv           = "HYSTERIA_BRUTAL_DEBUG"
	debugPrintInterval = 2

	// Rate randomisation. brutal paces at a fixed rate, which is what makes it
	// useful (it keeps a known link just below saturation) and also what makes
	// the resulting traffic pattern machine-like and therefore fingerprintable.
	// The pacer rate is therefore re-drawn once per window from a symmetric
	// distribution, so the long-run average still equals the configured rate
	// while the short-term rate is not constant.
	jitterPctEnv    = "HYSTERIA_BRUTAL_JITTER"     // percent, 0 disables
	jitterWindowEnv = "HYSTERIA_BRUTAL_JITTER_WIN" // duration, default 1s
	maxRateEnv      = "HYSTERIA_BRUTAL_MAX_RATE"   // bytes/s, 0 = derived cap

	defaultJitterPct    = 10
	defaultJitterWindow = time.Second
)

var _ congestion.CongestionControl = &BrutalSender{}

type BrutalSender struct {
	rttStats        congestion.RTTStatsProvider
	bps             congestion.ByteCount
	maxDatagramSize congestion.ByteCount
	pacer           *common.Pacer

	pktInfoSlots [pktInfoSlotCount]pktInfo
	ackRate      float64

	// rate randomisation and the hard ceiling on what brutal will send
	now          func() time.Time
	jitterPct    float64              // fraction of the target rate, 0 disables
	jitterWindow time.Duration        // how often the factor is re-drawn
	rateLimit    congestion.ByteCount // absolute ceiling; 0 = derived from bps
	rng          *rand.Rand
	jitterFactor float64
	jitterUntil  time.Time

	debug                 bool
	lastAckPrintTimestamp int64
}

type pktInfo struct {
	Timestamp int64
	AckCount  uint64
	LossCount uint64
}

func NewBrutalSender(bps uint64) *BrutalSender {
	debug, _ := strconv.ParseBool(os.Getenv(debugEnv))
	bs := newBrutalSender(bps, debug, envJitterPct(), envJitterWindow(), envRateLimit())
	return bs
}

// newBrutalSender builds a sender with explicit mitigation parameters, so the
// behaviour does not depend on the environment in tests.
func newBrutalSender(bps uint64, debug bool, jitterPct float64, jitterWindow time.Duration, rateLimit congestion.ByteCount) *BrutalSender {
	bs := &BrutalSender{
		bps:             congestion.ByteCount(bps),
		maxDatagramSize: congestion.InitialPacketSizeIPv4,
		ackRate:         1,
		now:             time.Now,
		jitterPct:       jitterPct,
		jitterWindow:    jitterWindow,
		rateLimit:       rateLimit,
		rng:             rand.New(rand.NewSource(time.Now().UnixNano())),
		jitterFactor:    1,
		debug:           debug,
	}
	bs.pacer = common.NewPacer(func() congestion.ByteCount {
		return bs.targetRate()
	})
	return bs
}

func envJitterPct() float64 {
	v := os.Getenv(jitterPctEnv)
	if v == "" {
		return defaultJitterPct / 100
	}
	pct, err := strconv.ParseFloat(v, 64)
	if err != nil || pct < 0 {
		return defaultJitterPct / 100
	}
	if pct > 90 {
		pct = 90
	}
	return pct / 100
}

func envJitterWindow() time.Duration {
	v := os.Getenv(jitterWindowEnv)
	if v == "" {
		return defaultJitterWindow
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return defaultJitterWindow
	}
	return d
}

func envRateLimit() congestion.ByteCount {
	v := os.Getenv(maxRateEnv)
	if v == "" {
		return 0
	}
	limit, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0
	}
	return congestion.ByteCount(limit)
}

// SetRateLimit sets a hard ceiling (bytes/s) on the rate brutal paces at,
// independently of loss compensation and rate randomisation. A limit of 0
// restores the derived cap.
func (b *BrutalSender) SetRateLimit(limit congestion.ByteCount) {
	b.rateLimit = limit
}

// rateCeiling is the maximum rate brutal is allowed to pace at: the configured
// limit when one was set, otherwise the worst case the loss compensation could
// already reach before (bps / minAckRate). Rate randomisation must never exceed
// this, so enabling it cannot raise the peak rate of a connection.
func (b *BrutalSender) rateCeiling() congestion.ByteCount {
	if b.rateLimit > 0 {
		return b.rateLimit
	}
	return congestion.ByteCount(float64(b.bps) / minAckRate)
}

// targetRate returns the rate to pace at right now: the configured bandwidth,
// compensated for loss, randomised by ±jitterPct and clamped to the ceiling.
func (b *BrutalSender) targetRate() congestion.ByteCount {
	if b.jitterPct > 0 {
		now := b.now()
		if now.After(b.jitterUntil) {
			b.jitterUntil = now.Add(b.jitterWindow)
			// symmetric around 1, so the average rate is unchanged
			b.jitterFactor = 1 + b.jitterPct*(2*b.rng.Float64()-1)
		}
	}
	rate := congestion.ByteCount(float64(b.bps) / b.ackRate * b.jitterFactor)
	if ceiling := b.rateCeiling(); rate > ceiling {
		rate = ceiling
	}
	return rate
}

func (b *BrutalSender) SetRTTStatsProvider(rttStats congestion.RTTStatsProvider) {
	b.rttStats = rttStats
}

func (b *BrutalSender) TimeUntilSend(bytesInFlight congestion.ByteCount) time.Time {
	return b.pacer.TimeUntilSend()
}

func (b *BrutalSender) HasPacingBudget(now time.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *BrutalSender) CanSend(bytesInFlight congestion.ByteCount) bool {
	return bytesInFlight <= b.GetCongestionWindow()
}

func (b *BrutalSender) GetCongestionWindow() congestion.ByteCount {
	rtt := b.rttStats.SmoothedRTT()
	if rtt <= 0 {
		return 10240
	}
	cwnd := congestion.ByteCount(float64(b.bps) * rtt.Seconds() * congestionWindowMultiplier / b.ackRate)
	if cwnd < b.maxDatagramSize {
		cwnd = b.maxDatagramSize
	}
	return cwnd
}

func (b *BrutalSender) OnPacketSent(sentTime time.Time, bytesInFlight congestion.ByteCount,
	packetNumber congestion.PacketNumber, bytes congestion.ByteCount, isRetransmittable bool,
) {
	b.pacer.SentPacket(sentTime, bytes)
}

func (b *BrutalSender) OnPacketAcked(number congestion.PacketNumber, ackedBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount, eventTime time.Time,
) {
	// Stub
}

func (b *BrutalSender) OnCongestionEvent(number congestion.PacketNumber, lostBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount,
) {
	// Stub
}

func (b *BrutalSender) OnCongestionEventEx(priorInFlight congestion.ByteCount, eventTime time.Time, ackedPackets []congestion.AckedPacketInfo, lostPackets []congestion.LostPacketInfo) {
	currentTimestamp := eventTime.Unix()
	slot := currentTimestamp % pktInfoSlotCount
	if b.pktInfoSlots[slot].Timestamp == currentTimestamp {
		b.pktInfoSlots[slot].LossCount += uint64(len(lostPackets))
		b.pktInfoSlots[slot].AckCount += uint64(len(ackedPackets))
	} else {
		// uninitialized slot or too old, reset
		b.pktInfoSlots[slot].Timestamp = currentTimestamp
		b.pktInfoSlots[slot].AckCount = uint64(len(ackedPackets))
		b.pktInfoSlots[slot].LossCount = uint64(len(lostPackets))
	}
	b.updateAckRate(currentTimestamp)
}

func (b *BrutalSender) SetMaxDatagramSize(size congestion.ByteCount) {
	b.maxDatagramSize = size
	b.pacer.SetMaxDatagramSize(size)
	if b.debug {
		b.debugPrint("SetMaxDatagramSize: %d", size)
	}
}

func (b *BrutalSender) updateAckRate(currentTimestamp int64) {
	minTimestamp := currentTimestamp - pktInfoSlotCount
	var ackCount, lossCount uint64
	for _, info := range b.pktInfoSlots {
		if info.Timestamp < minTimestamp {
			continue
		}
		ackCount += info.AckCount
		lossCount += info.LossCount
	}
	if ackCount+lossCount < minSampleCount {
		b.ackRate = 1
		if b.canPrintAckRate(currentTimestamp) {
			b.lastAckPrintTimestamp = currentTimestamp
			b.debugPrint("Not enough samples (total=%d, ack=%d, loss=%d, rtt=%d)",
				ackCount+lossCount, ackCount, lossCount, b.rttStats.SmoothedRTT().Milliseconds())
		}
		return
	}
	rate := float64(ackCount) / float64(ackCount+lossCount)
	if rate < minAckRate {
		b.ackRate = minAckRate
		if b.canPrintAckRate(currentTimestamp) {
			b.lastAckPrintTimestamp = currentTimestamp
			b.debugPrint("ACK rate too low: %.2f, clamped to %.2f (total=%d, ack=%d, loss=%d, rtt=%d)",
				rate, minAckRate, ackCount+lossCount, ackCount, lossCount, b.rttStats.SmoothedRTT().Milliseconds())
		}
		return
	}
	b.ackRate = rate
	if b.canPrintAckRate(currentTimestamp) {
		b.lastAckPrintTimestamp = currentTimestamp
		b.debugPrint("ACK rate: %.2f (total=%d, ack=%d, loss=%d, rtt=%d)",
			rate, ackCount+lossCount, ackCount, lossCount, b.rttStats.SmoothedRTT().Milliseconds())
	}
}

func (b *BrutalSender) InSlowStart() bool {
	return false
}

func (b *BrutalSender) InRecovery() bool {
	return false
}

func (b *BrutalSender) MaybeExitSlowStart() {}

func (b *BrutalSender) OnRetransmissionTimeout(packetsRetransmitted bool) {}

func (b *BrutalSender) canPrintAckRate(currentTimestamp int64) bool {
	return b.debug && currentTimestamp-b.lastAckPrintTimestamp >= debugPrintInterval
}

func (b *BrutalSender) debugPrint(format string, a ...any) {
	fmt.Printf("[BrutalSender] [%s] %s\n",
		time.Now().Format("15:04:05"),
		fmt.Sprintf(format, a...))
}
