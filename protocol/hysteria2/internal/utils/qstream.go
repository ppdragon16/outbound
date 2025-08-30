package utils

import (
	"github.com/daeuniverse/quic-go"
)

// QStream is a wrapper of quic.Stream that handles Close() in a way that
// makes more sense to us. By default, quic.Stream's Close() only closes
// the write side of the stream, not the read side. And if there is unread
// data, the stream is not really considered closed until either the data
// is drained or CancelRead() is called.
// References:
// - https://github.com/libp2p/go-libp2p/blob/master/p2p/transport/quic/stream.go
// - https://github.com/quic-go/quic-go/issues/3558
// - https://github.com/quic-go/quic-go/issues/1599
type QStream struct {
	quic.Stream
}

func (s *QStream) Close() error {
	s.Stream.CancelRead(0)  // Close read
	return s.Stream.Close() // Close write
}
