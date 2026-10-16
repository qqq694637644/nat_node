# nat_node: reverse SOCKS5 over existing frp XTCP (RSX1)

Python **3.13**, standard library only. Provides a loopback SOCKS5 server on
the mainland NAT node; an outbound Go agent in
[`qqq694637644/x-ui`](https://github.com/qqq694637644/x-ui)
connects **from the overseas VPS** through the already-running frpc XTCP Visitor.
TCP CONNECT and SOCKS5 UDP ASSOCIATE are both implemented.

## Direction (unchanged)

```text
Mainland NAT node                            Overseas VPS
app -> 127.0.0.1:1080 SOCKS5
       Python RSX1 mux :9312 <== XTCP ==>    frpc Visitor :6000
       frpc XTCP Proxy                            |
                                                Go RSX1 exit (active dial)
                                                    |
                                              TCP/UDP Internet egress
```

**Do not reverse the frpc roles.** The mainland runs the XTCP **Proxy**;
the overseas VPS runs the XTCP **Visitor** and actively initiates the connection.
Existing WARP+/SOCKS5 NAT-hole routing and frps are not modified.

## Start

Generate a private random secret (at least 16 characters); use the **same**
`REVERSE_SOCKS_TOKEN` environment variable on both machines. Never commit it.

Mainland NAT node:

```sh
export REVERSE_SOCKS_TOKEN='replace-with-a-long-random-secret'
python3.13 -m reverse_socks --socks 127.0.0.1:1080 --mux 127.0.0.1:9312
```

Mainland `frpc.toml` (add to existing config; keep your existing frps settings):

```toml
[[proxies]]
name = "rsx1_node"
type = "xtcp"
secretKey = "replace-with-your-frp-secret"
localIP = "127.0.0.1"
localPort = 9312
```

Overseas `frpc.toml` (add a Visitor to existing config):

```toml
[[visitors]]
name = "rsx1_outside"
type = "xtcp"
serverName = "rsx1_node"
secretKey = "replace-with-your-frp-secret"
bindAddr = "127.0.0.1"
bindPort = 6000
keepTunnelOpen = true
```

Build on the overseas VPS from the `x-ui` checkout, then start the exit:

```sh
go build -o reverse-socks-exit ./cmd/reverse-socks-exit
export REVERSE_SOCKS_TOKEN='replace-with-the-same-long-random-secret'
./reverse-socks-exit -visitor 127.0.0.1:6000
```

The same agent is available from the main x-ui executable:
`x-ui reverse-socks-exit -visitor 127.0.0.1:6000`.
The exit agent reconnects when frp restarts. Keep its process running using
your existing supervisor/systemd setup.

**The SOCKS and Python mux listener must remain on loopback.** No public port
is necessary on either side. The SOCKS service deliberately uses NO AUTH
for loopback applications; the RSX1 agent link requires the shared HMAC token.
Protect the underlying frp transport as appropriate for your deployment.

## Test traffic

Mainland TCP:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

This should report the **overseas VPS egress IP**. To exit via WARP instead,
route the Go exit agent's outbound target connections through WARP separately.
Using WARP only for the XTCP hole-punch does *not* route target connections
through WARP automatically.

For a UDP test, use any SOCKS5 UDP ASSOCIATE client and send DNS to
`1.1.1.1:53` through `127.0.0.1:1080`. The SOCKS5 UDP relay port is
allocated dynamically per association; the TCP control connection must remain
open for the lifetime of UDP forwarding.

## Validation

```sh
python3.13 -m unittest -v tests.test_protocol
```

The cross-language smoke tests run with the real Go agent binary, but do not
require a live frps/WARP deployment:

```sh
go build -o reverse-socks-exit ./cmd/reverse-socks-exit  # from x-ui/
cd ../nat_node
REVERSE_SOCKS_EXIT_BIN=../x-ui/reverse-socks-exit python3.13 -m unittest -v tests.test_end_to_end
```

Tests cover 1 MiB TCP echo throughput, 20 concurrent TCP sessions, TCP
half-close, 25 UDP echo round-trips, and automatic exit reconnect.
The printed MiB/s value is **local loopback throughput only**, not an estimate
of performance over cross-border WARP+/XTCP.

## Protocol and deliberately unsupported features

Wire version `RSX1`: the node sends `RSX1 || 32-byte random challenge`;
the exit responds with HMAC-SHA256(secret, challenge). Every later frame is
`type:1 || session_id:4 BE || payload_len:4 BE || payload`, with a maximum
65,535-byte payload. `OPEN_TCP` carries an RFC1928 address; `UDP_DATA`
contains an entire RFC1928 SOCKS5 UDP datagram. The node allocates session
IDs; TCP FIN supports half-closes. UDP association lifetime is tied to
its SOCKS control TCP connection. Receiver queues are bounded.

* No SOCKS BIND, SOCKS username/password, public SOCKS listener, route
  interception, TUN, SSH, or second KCP layer.
* SOCKS5 UDP with nonzero `FRAG` is dropped (no reassembly).
* UDP is transported over the reliable XTCP byte stream and can suffer
  head-of-line blocking. It is **not** native unreliable UDP transport.
* One authenticated Go exit agent at a time, up to 1,024 concurrent sessions.
* Protocol is fixed at RSX1: no legacy/compatibility negotiation.
