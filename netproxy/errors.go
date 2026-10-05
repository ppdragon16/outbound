package netproxy

import "fmt"

// Compile-time interface checks.
var _ error = (*ErrDatagramDropped)(nil)

// ErrDatagramDropped is the typed contract for a per-datagram event that must
// not take the session down. It covers both directions:
//
//   - read side: a received datagram was consumed and discarded (larger than
//     the caller's buffer, or its source address cannot be attributed), and the
//     stream stays aligned -- the next ReadFrom returns the next datagram;
//   - write side: a single datagram was refused before it hit the wire (e.g. it
//     cannot be serialized into a protocol length field), and subsequent
//     datagrams can still be written.
//
// Producers return it wrapping io.ErrShortBuffer in the common case. Consumers
// must treat it as a per-datagram event -- do not retire the connection, do not
// close the endpoint, and do not report the dialer unavailable. (Port of
// olicesx/outbound 7f939b6.)
//
// The Cause chain is preserved, so legacy consumers matching
// errors.Is(err, io.ErrShortBuffer) keep working across pins.
type ErrDatagramDropped struct {
	Cause error
}

func (e *ErrDatagramDropped) Error() string {
	return fmt.Sprintf("datagram dropped: %v", e.Cause)
}

// Unwrap exposes Cause so errors.Is and errors.As reach the underlying
// sentinel (io.ErrShortBuffer) through the wrapper.
func (e *ErrDatagramDropped) Unwrap() error { return e.Cause }

// DatagramDropped wraps cause in the datagram-dropped contract. Producers
// that drained an oversized datagram pass io.ErrShortBuffer as the cause.
func DatagramDropped(cause error) error {
	return &ErrDatagramDropped{Cause: cause}
}
