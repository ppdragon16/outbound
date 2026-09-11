/*
 * SPDX-License-Identifier: MIT
 *
 * Port of the semantics pin from koutbound 8e1ba9f (fix(bbr3): stop reading a
 * ring wrap-around as a packet-number resend), adapted to this fork's
 * chromium-lineage sampler. Here a duplicate send of an already-tracked packet
 * number is refused by the pn-indexed queue instead of aliased onto a foreign
 * slot, so the property to pin is narrower: the FIRST send's record survives
 * and stays the anchor of the delivery-rate sample.
 */

package bbrv3

import (
	"testing"
	"time"

	"github.com/daeuniverse/quic-go/congestion"
)

func TestResendKeepsTheFirstSendRecord(t *testing.T) {
	b := newBandwidthSampler(10)
	base := time.Now()

	// Warm-up: the very first packet on a connection produces no send-rate
	// sample (chromium A0 semantics, bandwidth_sampler.go: lastAckedPacketSentTime
	// is zero), so anchor the pinned record on a second packet.
	b.OnPacketSent(base, 1, 1200, 1200, true)
	b.OnCongestionEvent(
		base.Add(5*time.Millisecond),
		[]congestion.AckedPacketInfo{{PacketNumber: 1, BytesAcked: 1200, ReceivedTime: base.Add(5 * time.Millisecond)}},
		nil, 0, 0, 0,
	)

	const pn congestion.PacketNumber = 2
	const firstSendBytes congestion.ByteCount = 1200

	// The pinned send at t=10ms.
	b.OnPacketSent(base.Add(10*time.Millisecond), pn, firstSendBytes, firstSendBytes, true)

	// A re-send of the SAME packet number at t=20ms with a different size: the
	// record must not be overwritten.
	b.OnPacketSent(base.Add(20*time.Millisecond), pn, 500, 500, true)

	// Queue level: the duplicate insert was refused, the entry is the first
	// send's.
	entry := b.connectionStateMap.GetEntry(pn)
	if entry == nil {
		t.Fatal("first send record missing from the connection state map")
	}
	if entry.size != firstSendBytes {
		t.Fatalf("first send record was overwritten: size = %d, want %d", entry.size, firstSendBytes)
	}
	if !entry.sentTime.Equal(base.Add(10 * time.Millisecond)) {
		t.Fatalf("first send record was overwritten: sentTime = %v, want %v", entry.sentTime, base.Add(10*time.Millisecond))
	}

	// Sampler level: acknowledging the packet must produce the sample anchored
	// on the FIRST send -- rtt measured from t=10ms (50 ms), not from the
	// duplicate's t=20ms (40 ms).
	sample := b.OnCongestionEvent(
		base.Add(60*time.Millisecond),
		[]congestion.AckedPacketInfo{{PacketNumber: pn, BytesAcked: firstSendBytes, ReceivedTime: base.Add(60 * time.Millisecond)}},
		nil,
		0, 0, 0,
	)
	if sample.sampleRtt != 50*time.Millisecond {
		t.Fatalf("delivery sample anchored on the wrong send: sample_rtt = %v, want 50ms (measured from the first send)", sample.sampleRtt)
	}
}

// TestEmplaceRefusesDuplicateAndOutOfOrderInserts pins the queue-level guard
// the property above rests on.
func TestEmplaceRefusesDuplicateAndOutOfOrderInserts(t *testing.T) {
	q := newPacketNumberIndexedQueue[connectionStateOnSentPacket](8)
	base := time.Now()

	if !q.Emplace(1, &connectionStateOnSentPacket{sentTime: base, size: 1200}) {
		t.Fatal("first insert rejected")
	}
	if q.Emplace(1, &connectionStateOnSentPacket{sentTime: base.Add(time.Second), size: 1}) {
		t.Fatal("duplicate insert of the same packet number accepted")
	}
	if q.Emplace(0, &connectionStateOnSentPacket{sentTime: base, size: 1}) {
		t.Fatal("out-of-order insert below the window accepted")
	}
	entry := q.GetEntry(1)
	if entry == nil || entry.size != 1200 {
		t.Fatalf("first record clobbered: %+v", entry)
	}
}
