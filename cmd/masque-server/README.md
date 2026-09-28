# masque-server

A standalone MASQUE proxy server (RFC 9298 CONNECT-UDP + plain HTTP/3 CONNECT)
for outbound's `masque://` links.

It exists because no mainstream proxy core ships a masque *server*: sing-box and
Xray have none, mihomo only a client, and Cloudflare's WARP masque service is
bound to its own registration token. The protocol is standard HTTP/3, so any
RFC 9298 client can use this server; the interop target is outbound's own client.

What it serves:

| Target | Wire |
| --- | --- |
| TCP | plain HTTP/3 `CONNECT`, `:authority` = target, raw bytes on the stream after a 2xx |
| UDP | extended `CONNECT` (`:proto: connect-udp`) to `/.well-known/masque/udp/{host}/{port}/`, payloads as RFC 9297 HTTP datagrams with context id 0 |

The server is independent of dae: it imports only `protocol/masque/server`, the
QUIC stack and utls. Deploy the binary on whatever host should act as the proxy.

**The protocol carries no authentication.** Anyone who can reach the UDP port can
use the server as an open relay unless you restrict it at the network layer or
with `-allow-targets`. See [Security](#security).

## Build

Requirements: Go 1.26 or newer (see `go.mod`), and network access for module
downloads. Build from a checkout of this repository — the `go.mod` pins the QUIC
stack to the `ppdragon16/quic-go` fork via `replace`, which the masque HTTP/3 and
capsule support requires.

```sh
# the repository that carries this command and the fork pin it needs
git clone https://github.com/ppdragon16/outbound
cd outbound
go build -o masque-server ./cmd/masque-server
```

For a deployment, check out the release you intend to run first, then build, so
the fork pin is the one you validated:

```sh
git checkout <tag-or-commit>        # e.g. the tag that ships this command
go build -trimpath -ldflags '-s -w' -o masque-server ./cmd/masque-server
```

Cross-compile (the binary is pure Go; CGO is not needed):

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o masque-server-linux-amd64 ./cmd/masque-server
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o masque-server-linux-arm64 ./cmd/masque-server
```

`go install ./cmd/masque-server` works from the checkout as well (it installs
into `$GOBIN`).

### Do not use `go install pkg@version`

Installing by module version does not work for this command, for two reasons:

- `replace` directives in the *dependency's* `go.mod` are ignored in module
  mode, so the build would use upstream `github.com/daeuniverse/quic-go` and
  fail on the fork-only APIs;
- the fork publishes tags under `github.com/ppdragon16/outbound`, whose `go.mod`
  still declares `module github.com/daeuniverse/outbound`, so requiring it
  directly is a module path mismatch.

If you want to depend on these packages from your own module, add both replaces
yourself:

```
replace github.com/daeuniverse/outbound => github.com/ppdragon16/outbound <tag>
replace github.com/daeuniverse/quic-go => github.com/ppdragon16/quic-go <tag>
```

The masque datagram path needs `quic-go >= v0.0.0-next.utls.12` (a datagram for
an unregistered stream used to kill the whole datagram receive loop) and the
address-ownership fix in `>= v0.0.0-next.utls.13`; this repository's pin already
satisfies both.

## Run

```
masque-server -listen :443 -cert /etc/masque/fullchain.pem -key /etc/masque/privkey.pem
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-listen` | `:443` | UDP listen address (QUIC is UDP only) |
| `-cert` | — | TLS certificate (PEM), required; chain file if the issuer sends intermediates |
| `-key` | — | TLS private key (PEM), required |
| `-idle-timeout` | `5m` | how long a UDP flow may stay silent before its relay is dropped |
| `-mtu` | `0` | QUIC Initial packet size (path MTU budget); `0` keeps the safe default 1280. Set only after measuring the path (see [Path MTU](#path-mtu-and-the-udp-relay-budget)) |
| `-congestion-control` | `bbrv3` | relay send-direction controller (what the client downloads through); `bbr` selects BBRv1 |
| `-allow-targets` | empty | comma-separated CIDRs of allowed relay targets; empty allows all (**open relay**) |
| `-v` | off | log every relayed target and rejection |

With `-allow-targets`, only targets given as literal IPs inside the listed
prefixes are relayable; hostname targets are refused (the check has no name to
resolve). Examples:

```sh
# only allow the private ranges and one public resolver, as a choke point
masque-server -listen :443 -cert cert.pem -key key.pem \
  -allow-targets 10.0.0.0/8,192.168.0.0/16,1.1.1.1/32 -v
```

## TLS certificates

The client validates the certificate against the SNI in its link, so use a real
certificate for a real domain. Any ACME client works as long as the server can
read the files; the QUIC listener needs UDP only — certificate issuance over
HTTP-01/DNS-01 needs its own port 80 or DNS access:

```sh
# one-shot renewal hook style; run your ACME client of choice
certbot certonly --standalone -d proxy.example.com
install -m 640 /etc/letsencrypt/live/proxy.example.com/fullchain.pem /etc/masque/fullchain.pem
install -m 640 /etc/letsencrypt/live/proxy.example.com/privkey.pem   /etc/masque/privkey.pem
```

A self-signed certificate also works if clients set `insecure=1` (see below).

## systemd

`/etc/systemd/system/masque-server.service`:

```ini
[Unit]
Description=MASQUE proxy server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/masque-server \
  -listen :443 \
  -cert /etc/masque/fullchain.pem \
  -key /etc/masque/privkey.pem \
  -allow-targets 10.0.0.0/8,192.168.0.0/16
Restart=always
RestartSec=2
# only needed when binding a privileged port as a non-root user
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
# run under a dedicated user that can read the certificate and key, e.g.
# User=masque
# Group=masque

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload && systemctl enable --now masque-server
```

Firewall: allow the UDP port only.

```sh
ufw allow 443/udp
# or: nft add rule inet filter input udp dport 443 accept
```

Because the traffic is ordinary HTTP/3, the server can also share a port and a
certificate with a real website: an active prober sees a normal H3 endpoint.

## Client link (dae / outbound)

```
masque://proxy.example.com:443?sni=proxy.example.com&zero_rtt=1#masque-node
```

| Query | Meaning |
| --- | --- |
| `sni` / `peer` | TLS SNI (defaults to the proxy host) |
| `insecure=1` | skip certificate verification (self-signed deployments) |
| `zero_rtt=1` | send the first CONNECT / CONNECT-UDP as QUIC 0-RTT early data on a resumed session |
| `mtu` | QUIC Initial packet size, e.g. `mtu=1452` on a path that carries 1500-byte datagrams (see [Path MTU](#path-mtu-and-the-udp-relay-budget)) |
| `congestion_control` | `bbrv3` (default) or `bbr` (BBRv1); lossy long-RTT paths sometimes do better on BBRv1 |
| `strict=1` | make dialing wait for the proxy's CONNECT response, so a refused target fails at dial time |

Dials are optimistic by default: the CONNECT request is sent and the dial
returns immediately, with the response status validated on the first read. The
response is only written after the proxy has dialed the target, so waiting for
it serializes the QUIC handshake and the target dial into the dial path — two
round trips where protocols with a fire-and-forget connect pay one. Add
`strict=1` when a refused target must fail the dial itself (a client that
measures node latency, such as dae, otherwise reports the tunnel's real
round-trip instead of handshake + target dial).

`zero_rtt` needs the server to accept 0-RTT; this server does by default
(`http3.Server` sets `Allow0RTT: true` unless a custom `QUICConfig` is given).
Early data is replayable, which is why it stays opt-in per link.

## Path MTU and the UDP relay budget

UDP datagrams travel one per QUIC datagram, so the tunnel's budget is the outer
path MTU minus roughly 50 bytes of IPv6/UDP/QUIC headers and framing. The server
accepts inner datagrams up to 1400 bytes; whether they are deliverable depends
on the path.

Both ends start from the QUIC default Initial packet size (1280), which fits
every path, and rely on QUIC path MTU discovery to raise the budget. Discovery
needs the socket's don't-fragment capability and needs traffic to probe, so
large datagrams can be dropped for the first seconds after a connection (or
until other traffic drives the probes). The inner connection (typically a
browser's QUIC) sees those drops as loss and shrinks its own packet size, which
is the normal tunnel MTU trade-off.

If the path is known to carry 1500-byte datagrams, start bigger on both ends so
the full budget is available immediately:

```sh
# server
masque-server -listen :7443 -cert ... -key ... -mtu 1452
# client link
masque://[2001:db8::1]:7443?sni=proxy.example.com&mtu=1452&zero_rtt=1#node
```

Measure before setting it: an Initial packet of `mtu` bytes needs `mtu + 48`
bytes of path MTU (IPv6) or `mtu + 28` (IPv4), and an oversized Initial is
dropped by any hop whose MTU is smaller, after which the handshake never
completes (`timeout: no recent network activity`). From the client host:

```sh
ping -6 -M do -s 1400 proxy.example.com   # succeeds => path MTU >= 1448
ping -6 -M do -s 1452 proxy.example.com   # succeeds => mtu=1452 is safe
```

Leave `mtu` unset when unsure: the handshake always works and the budget grows
to whatever the path supports.

## Security

- **No authentication, no per-user accounting.** Treat the port as open: use
  firewall rules (source allowlists), a private network, or `-allow-targets` to
  restrict where the server can connect.
- **`-allow-targets` limits egress, not ingress**: it stops the server from
  being used to reach internal services, but anyone who can reach the port can
  still relay through it to allowed targets.
- Early data (0-RTT) is replayable by an observer; the CONNECT/CONNECT-UDP
  requests replayed this way are idempotent openings, but keep `zero_rtt` off
  where that matters.
- No rate limiting or connection accounting is implemented.

## Verification

The server package is covered by interop tests that drive the real
`protocol/masque` client against it — TCP half-close, a UDP datagram round trip,
`zero_rtt` including the datagram path on a resumed session, and the rejection
paths (denied target 403, unreachable upstream 502):

```sh
go test ./protocol/masque/server/ -v
```

To smoke-test a deployment end to end, point a dae node or an outbound link at
the server and fetch something through it (`zero_rtt=1` to exercise the resumed
path).

## License

See the [LICENSE](../../LICENSE) file for license rights and limitations.
