# RSX3 Direct QUIC over IPv6 + DDNS (independent of FRP)

This is a **new opt-in mode**. The existing `python -m reverse_socks` FRP/XTCP
invocation, local 9312/9313/9314 ports, STUN, WARP and diagnostics remain
unchanged and require **no additional pip packages**.

## Network model

`@text
Windows: App -> SOCKS5 127.0.0.1:1080 -> Python RSX3
                            |
              IPv6 [::]:8080 / UDP / QUIC
                            ^
                      DDNS AAAA
                            |
VPS Linux: x-ui Go QUIC Client -> native VPS TCP/UDP
                                -> optional loopback Xray SOCKS5
`@

- No frpc, frps, STUN, XTCP, WARP transport or IPv4 DMZ is needed in this mode.
- Each SOCKS5 TCP session uses a separate QUIC bidirectional stream.
- SOCKS5 UDP uses QUIC DATAGRAM, up to 1100 bytes including the RSX3 session ID.
- Linux verifies a pinned leaf certificate SHA-256, DNS SAN, certificate dates,
  and the existing RSX3 per-stream HMAC.
- The separate FRP Diagnostics feature is not implemented for Direct QUIC yet.

## Windows PowerShell 7

Use Python 3.13 and prepare a DNS hostname whose **AAAA** points to the
Windows host's current global unicast IPv6. Configure your router's DDNS client,
a scheduled updater, or your DNS provider to update it on delegated-prefix
changes. This project does **not** manage DNS provider credentials or update APIs.

From the `nat_node` checkout:

`@powershell
py -m pip install -r requirements-direct-quic.txt
New-Item -ItemType Directory -Force C:\rsx3 | Out-Null
py scripts/create_direct_quic_cert.py --hostname rsx3.example.com --cert C:\rsx3\quic-cert.pem --key C:\rsx3\quic-key.pem

$env:REVERSE_SOCKS_TOKEN = '<same-strong-random-secret-on-Linux>'
py -m reverse_socks --protocol rsx3 --direct-quic `
  --socks 127.0.0.1:1080 --quic-listen "[::]:8080" `
  --quic-cert C:\rsx3\quic-cert.pem --quic-key C:\rsx3\quic-key.pem
`@

Copy only the printed certificate fingerprint (never the private key) to x-ui.
Restrict the private key file to the Windows service account. The helper
creates a 365-day self-signed certificate; rotate the pin in x-ui when renewed.

If SOCKS5 1080 is in use by the original FRP instance, stop that instance
or choose a different free local `--socks` port. Both features remain
available but cannot share the same listening TCP port.

Allow inbound IPv6 UDP 8080 to the Windows host in the router/host security
policy as required. Do not expose local SOCKS5 1080 or 9312. UDP 8080 is a
candidate, not a protocol requirement; use any IPv6-reachable UDP port.

## x-ui

Open **反向 SOCKS5 / IPv6 DDNS**, not the historical **反向 SOCKS5 / WARP** page.

1. Fill DDNS hostname, IPv6 UDP port, SHA-256 certificate fingerprint and RSX3 token.
2. Select native VPS TCP/UDP egress or explicit local Xray SOCKS5 (e.g. 127.0.0.1:40001).
3. Enable and save. Linux resolves only AAAA and establishes authenticated QUIC/RSX3.

On reconnect the Go client resolves AAAA anew; every 60 seconds it checks
whether the active IPv6 is still in the DDNS set, reconnecting on removal.
A temporary DNS outage does not proactively stop a working connection.
No automatic fallback to FRP/WARP occurs. Keep the x-ui admin panel secured:
as with the legacy settings, the token is persisted to the panel DB.

## Optional standalone Go smoke command

`@bash
REVERSE_SOCKS_TOKEN='<same-strong-random-secret>' \
./reverse-socks-exit -direct-ddns rsx3.example.com -direct-port 8080 \
  -direct-cert-sha256 '<64-hex-digits>' -native-egress
`@

Do not run standalone and x-ui managed direct clients simultaneously.
Without `-direct-ddns` the standalone program keeps the original FRP
transport without alteration.

## Validation and rollback

`@powershell
py -m unittest tests.test_direct_quic
py -S -m unittest tests.test_dependencies tests.test_protocol
`@

The first test requires aioquic; the second confirms the legacy mode still
uses only the Python standard library. For rollback, disable the IPv6/DDNS
page and use the unchanged FRP/XTCP/WARP setup. No existing FRP configuration
needs to be deleted.
