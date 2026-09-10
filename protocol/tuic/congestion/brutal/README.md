# brutal

Paces at a fixed, user-supplied rate (the `tx` / `cwnd` value on hysteria2 and
tuic links), compensating for loss with the measured ACK rate. It is the right
controller when the link capacity is known and bufferbloat must be avoided.

## Rate randomisation and rate limit

A perfectly constant rate is easy to tell apart from ordinary traffic. The
sender therefore re-draws its pacing rate once per window from a symmetric
distribution, so the **average** rate still equals the configured value while
the short-term rate is not constant. The rate is additionally clamped to a hard
ceiling, so randomisation (and the loss compensation) can never raise the peak
rate of a connection above `bps / minAckRate` — or above an explicitly
configured limit.

| Variable | Default | Meaning |
|---|---|---|
| `HYSTERIA_BRUTAL_JITTER` | `10` | Percentage the pacing rate is randomised by, symmetric around the configured rate. `0` disables randomisation and restores the exact constant rate. |
| `HYSTERIA_BRUTAL_JITTER_WIN` | `1s` | How often the random factor is re-drawn. |
| `HYSTERIA_BRUTAL_MAX_RATE` | derived | Absolute ceiling in bytes per second. Defaults to `bps / 0.8`, the worst case the loss compensation could already reach. |
| `HYSTERIA_BRUTAL_DEBUG` | off | Periodic ACK-rate logging. |

`SetRateLimit` sets the ceiling programmatically. Note that the mitigation only
shapes the *sending rate*; it does not hide the transport itself — when obfs is
enabled the whole connection is already unrecognisable, and when it is not, the
QUIC/TLS handshake is the more distinctive feature.

## Tests

`brutal_test.go` covers the rate invariants: the jitter stays within its bounds,
keeps the long-run average (checked both on the rate function and on what the
pacer actually puts on the wire), is stable within a window and re-drawn between
windows, never exceeds the loss-compensation peak, and respects an explicit rate
limit. It also covers the environment switches, including their guard rails.
