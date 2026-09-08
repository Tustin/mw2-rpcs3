# Modern Warfare 2 RPCS3 Private-Match Emulator

A clean-room Go research backend for restoring private-match connectivity to **Call of Duty: Modern Warfare 2** on RPCS3.

## Current status

This repository now provides a clean-room compatibility-server foundation with
two deliberately separate paths:

- a retail MW2 authentication and encrypted LSG path on TCP `3074`; and
- an older experimental lobby/session scaffold on TCP `3075`.

Prior RPCS3 runs have completed dynamic authentication, the LSG hello, and
encrypted service requests. The server implements minimal title-utilities, DML,
bandwidth, stats, and retail storage handlers. The corrected storage path
advertises and serves the bundled `playlists.info` using the exact bytes loaded
at runtime; its operation-8 and operation-5 layouts are backed by
client-disassembly evidence and golden tests.
The retail parser also confirms that playlist ID `0`, the gametype alias, the
weighted map entry, and the solo party bounds produce a visible, selectable
row. A new live RPCS3 recheck with sensitive diagnostics is still required.

Retail matchmaking is service `5`. The exact request schemas for operations
`1` through `5` are recovered. The retail `3074` path now implements
create/update/delete plus zero/nonempty `findSessions` against one shared,
thread-safe directory, with generated session ID/key material and exact
result objects. All seven query-field meanings are recovered; only the proven
required-free-slot comparison is applied because the other historical backend
comparators are absent from the client. Operation `4` and live RPCS3
two-client confirmation remain pending. Automated harnesses cover both
synthetic encrypted LSG clients and two real TCP authentication exchanges
through issued one-use LSG tickets, storage, and candidate deletion. The
session directory on `3075` remains a separate research scaffold.

The retail directory has two explicit emulator hardening policies: a
4096-record cap and update/delete ownership bound to the creating LSG
connection. Owned records are reclaimed when that authenticated connection
closes, preventing abandoned records from permanently consuming the bounded
directory. Authenticated LSG connections use a separate five-minute idle limit,
which safely exceeds the recovered 180-second host refresh cadence. None of
these policies is claimed as a recovered historical backend rule.
See [CURRENT_PROGRESS.md](CURRENT_PROGRESS.md) and [the service-5 protocol
note](docs/demonware-matchmaking.md). The current milestone's evidence,
validation boundary, and continuation checklist are in
[docs/MILESTONE_HANDOVER.md](docs/MILESTONE_HANDOVER.md).

Public-address and NAT discovery are separate recovered UDP exchanges. The
server accepts exact MW2 v2 `1e 02 00` and `14 02 00 command` requests on
primary UDP `3074`; classification commands `3` and `2` reply from alternate
UDP `3075`. Exact later peer QoS and NAT-traversal packet codecs are recovered,
as are the complete old-bdDTLS Init/InitAck/CookieEcho/CookieAck/Error/Data
formats, authentication scope, and replay window.
The current legacy introducer's strict 29-byte, embedded-destination
type-`0x0a` -> type-`0x0b` relay was independently reproduced and is
implemented on primary UDP `3074` behind a disabled-by-default safety flag;
QoS and secure title traffic remain peer-to-peer. Live two-client confirmation
remains pending. See the
[IP-discovery protocol
note](docs/demonware-ip-discovery.md) and [peer protocol
notes](docs/demonware-peer-qos.md) ([DTLS](docs/demonware-peer-dtls.md)).

## Scope

The target is two RPCS3 clients running `BLUS30377` update `1.14`, signed into
RPCN, discovering and joining an MW2 match over the recovered retail control
plane. Stats/profile behavior is implemented only as needed to complete the
online bootstrap. Leaderboards, physical PS3 consoles, relays beyond the
proven introducer forwarder, anti-cheat, and host migration remain out of
scope.

RPCN remains responsible for PSN-like identity, friends, presence, invitations, NP tickets, and standard NP signaling. This service is intended to provide only the title-specific control plane proven necessary through capture. Gameplay should remain directly between clients.

## Build and test

Requirements: Go 1.25.12 or newer in the 1.25 line, or Docker.

```bash
go test ./...
go test -race ./...
go build ./cmd/mw2-server
go build ./cmd/mw2-inspect
```

Start locally:

```bash
MW2_LOG_LEVEL=debug go run ./cmd/mw2-server
```

Or with Docker Compose, replacing the example with the IPv4 address reachable
by the game clients. Use the Hyper-V VM's LAN IPv4 for local clients and the
cloud server's public IPv4 for remote clients:

```bash
cat > .env <<'EOF'
MW2_NAT_ADVERTISED_IP=192.168.1.10
MW2_DNS_REDIRECT_IP=192.168.1.10
# Set only when host port 80 is occupied by another service:
# MW2_HTTP_HOST_PORT=18080
EOF
docker compose up --build
```

Configure the PS3 or RPCS3 DNS server as that same IPv4. The Compose stack
runs dnsmasq on TCP/UDP `53`; dnsmasq listens on all container interfaces and
returns `MW2_DNS_REDIRECT_IP` for the MW2 authentication, LSG, and EZ Patch
hostnames. The host must make TCP/UDP `53` reachable and must not already have
a DNS service bound to those ports.

Default listeners:

- DNS TCP/UDP `53`;
- EZ Patch and health/metrics HTTP on host port `80` by default, configurable
  through `MW2_HTTP_HOST_PORT`;
- retail authentication and LSG TCP `3074`, exercised by prior RPCS3 runs;
- recovered MW2 public-address/NAT discovery UDP `3074` plus alternate reply
  source UDP `3075`, both of which coexist with TCP;
- experimental custom lobby TCP `3075`, not a retail Demonware service.

## Configuration

All configuration is environment-based:

- `MW2_AUTH_ADDR`, default `:3074`
- `MW2_LOBBY_ADDR`, default `:3075`
- `MW2_NAT_ADDR`, default `:3074` (primary UDP discovery socket)
- `MW2_NAT_ALT_ADDR`, default `:3075` (alternate UDP reply-source socket; its
  port must differ from the primary port)
- `MW2_NAT_ADVERTISED_IP`, default blank for native runs (canonical
  client-reachable alternate/source-check IPv4 for `0x15` replies and the
  service-18 bandwidth upload target; otherwise the alternate socket's
  specific bind or a route-derived IPv4)
- `MW2_DNS_REDIRECT_IP`, Docker-only client-reachable IPv4 returned by dnsmasq;
  the root Compose stack defaults it to `MW2_NAT_ADVERTISED_IP`
- `MW2_HTTP_HOST_PORT`, Docker-only host port for EZ Patch HTTP, default `80`;
  the game's stock EZ Patch URL requires port `80`, so an alternate port needs
  an existing reverse proxy or equivalent port-80 forwarding rule
- `MW2_NAT_RELAY_ENABLED`, default `false` (enables the exact unauthenticated
  introducer forwarder; use only in an isolated/trusted lab)
- `MW2_LSP_ADDR`, default `:2005` (UDP LSP server-list listener)
- `MW2_LSP_MESSAGE`, default `MW2 RPCS3 LSP`
- `MW2_LSP_VERSION`, default `361`
- `MW2_LSP_MAX_SERVERS`, default `120`
- `MW2_HTTP_ADDR`, default `:8080`
- `MW2_LOG_LEVEL`, one of `debug`, `info`, `warn`, or `error`
- `MW2_LOG_SENSITIVE`, default `false` (development-only credential, key, raw
  frame, and decrypted payload logging; never publish its output unredacted)
- `MW2_MAX_FRAME_BYTES`, default 1 MiB, valid range 64 bytes to 16 MiB
- `MW2_BANDWIDTH_SEND_DURATION_MS`, default `50` (service-18 request value; override for compatibility testing)
- `MW2_BANDWIDTH_FINALIZE_RECEIVE_PERIOD_MS`, default unset (experimental override for the measured service-18 finalize period)
- `MW2_READ_TIMEOUT`, default `30s`
- `MW2_WRITE_TIMEOUT`, default `10s`
- `MW2_SESSION_TTL`, default `2m` (experimental TCP-3075 session scaffold
  only; the retail service-5 directory does not invent a backend TTL)
- `MW2_CAPTURE_ENABLED`, default `false`
- `MW2_CAPTURE_DIR`, default `captures`
- `MW2_PLAYLISTS_FILE`, default runtime fallbacks include `./playlists.info`
- `MW2_MOTD`, independently authored text returned by the experimental storage service

Endpoints:

- `GET /healthz`
- `GET /readyz`
- `GET /metrics`

## RPCS3/RPCN lab setup

1. Use a legally obtained `BLUS30377` installation updated to `1.14` on both clients.
2. Record the exact RPCS3 build/commit, firmware, patches, DLC inventory, and RPCN version.
3. Create separate RPCS3 profiles and RPCN accounts. Set Network Status to **Connected** and PSN Status to **RPCN**.
4. Start with both clients and the server on one LAN. Validate the title
   protocol and recovered NAT-classification exchange before testing traversal.
5. Enable focused RPCS3 logging for `sys_net`, `rpcn`, and signaling. Keep logs private until credentials and tokens are removed.
6. Capture DNS and network metadata with Wireshark or tcpdump on the host interface and loopback where applicable.
7. Inventory each hostname, destination, port, transport, TLS SNI, connection order, packet length, retry, timeout, and menu transition.
8. Add RPCS3 IP/Host Switch entries one hostname at a time after the original hostname is observed. Do not use a wildcard initially. The exact mapping syntax and hostnames must come from the current RPCS3 documentation and the captured title behavior.
9. If redirection reaches the server but TLS or application validation fails, stop and record the evidence. Do not disable security checks server-side or claim success; a narrowly scoped RPCS3 game patch requires separate review.

RPCN commonly uses TCP `31313`, its UDP endpoint helper uses `3657`, and RPCS3
peer signaling commonly uses UDP `3658`. These RPCN values are separate from
MW2's captured auth, LSG, and discovery endpoints.

## Capture workflow

Raw capture is disabled by default because packets may contain account material.

```bash
MW2_CAPTURE_ENABLED=true MW2_CAPTURE_DIR=./captures go run ./cmd/mw2-server
```

Capture records are JSON Lines with timestamp, listener, direction, remote address, original length, SHA-256, and a bounded hexadecimal payload. Common textual credential labels are redacted, but binary secrets cannot be identified reliably. Review every record manually before sharing or committing it. `captures/*` is ignored by Git.

Ordinary server logs intentionally omit raw authorization tickets, session
keys, decrypted payload bytes, and frame hex. Enable packet capture only for a
controlled debugging session and treat its output as secret material.

For an isolated development run, enable complete protocol diagnostics:

```bash
MW2_LOG_LEVEL=debug MW2_LOG_SENSITIVE=true go run ./cmd/mw2-server
```

This logs authentication tickets, platform/LSG/session keys, raw records,
decrypted LSG request payloads, plaintext replies, and encrypted frames. It
also emits the complete advertised publisher-file set, selected operation-5
filename, playlist metadata, byte length, and SHA-256 fields plus a warning
when repeated operation-8 replies are not followed by operation 5. Set
`MW2_MOTD` to override the built-in message-of-the-day text. Treat the complete
log as credential-bearing.

Inspect a raw stream encoded with this project's experimental frame envelope:

```bash
go run ./cmd/mw2-inspect ./path/to/stream.bin
```

Inspect a server capture file:

```bash
go run ./cmd/mw2-inspect -jsonl ./captures/capture-YYYYMMDD.jsonl
```

The inspector can decode server captures when the corresponding generated
session material is available. An official retail PCAP alone does not contain
the PS3 platform key needed to recover its encrypted LSG session. Preserve
original PCAPs outside the repository and add only sanitized, legally shareable
fixtures to `testdata/`.

## Retail authentication and LSG

RPCS3 host redirection should map:

```text
mw2-ps3-auth.mmp3.demonware.net=<SERVER_IP>
mw2-ps3-lsg.live.mmp3.demonware.net=<SERVER_IP>
mw2-stun.us.demonware.net=<SERVER_IP>
mw2-stun.eu.demonware.net=<SERVER_IP>
```

The TCP `3074` listener distinguishes the initial auth exchange from the
follow-up LSG connection. It generates the auth tickets and session material,
consumes the one-use LSG ticket, completes the hello, then decrypts and
dispatches retail service tasks. Unsupported service/operation pairs are logged
with their correctly decoded packed operation ID and receive a protocol error
reply so runtime discovery can continue.

## MW2 public-address and NAT discovery

The two captured `mw2-stun.*.demonware.net` names use a compact proprietary UDP
exchange, not RFC STUN. Exact `1e 02 00` requests receive a nine-byte `0x1f`
observed-address reply. Exact `14 02 00 command` requests accept commands `0`,
`3`, and `2` and receive a 15-byte `0x15` reply containing the observed client
endpoint and advertised server endpoint. Command `0` replies from the primary
socket; commands `3` and `2` reply from the alternate socket.

Docker users must set `MW2_NAT_ADVERTISED_IP` to the host's client-reachable
IPv4 and publish/forward both `3074/udp` and `3075/udp`; container route
discovery cannot determine the host's public/LAN address. The advertised
IPv4 at the primary port must also route to the primary listener because the
client sends command `2` to that endpoint. The primary listener also performs
the exact introducer relay: a strict 29-byte type-`0x0a` packet with
little-endian version `>=2` is forwarded to its embedded destination after
changing only the type to `0x0b`. The central service does not answer QoS
probes or carry secure title traffic; the selected game host and seeker do.

The relay is disabled by default because the historical packet contains no
server-verifiable credential and its embedded destination controls where the
server sends UDP. Enable `MW2_NAT_RELAY_ENABLED=true` only on an isolated or
trusted test network; do not expose this research forwarder as a public
internet service.

## Experimental post-authentication protocol envelope

The current lobby development frame uses a 12-byte big-endian header:

- byte 0: kind (`1` request, `2` response, `3` error)
- byte 1: service ID
- byte 2: task ID
- byte 3: flags
- bytes 4-7: transaction ID
- bytes 8-11: payload length

This is not asserted to be MW2's retail format. Replace or adapt it only when captures establish exact behavior. Unknown service/task pairs return an error frame rather than closing the connection.

Experimental services are:

- service `1`, task `1`: identity login for build string `BLUS30377-1.14`;
- service `2`, task `1`: static object lookup (`motd`, `playlist`);
- service `3`, tasks `1-5`: create, find, join, leave, and heartbeat private sessions.

## Validation gates

1. Live-confirm corrected storage operation `8` with the exact loaded byte
   length and SHA-256.
2. Capture operation `5` and confirm the client parses the exact byte sequence
   advertised by operation `8`.
3. Confirm the client issues the recovered service-5 operation-5 query and
   accepts both zero- and nonempty-result replies.
4. Run two distinct RPCN accounts through simultaneous LSG sessions and record
   whether the current synthetic game-ticket identity appears in any later
   request.
5. Live-confirm create/find/update/delete and compare the post-find peer
   QoS/traversal and DTLS transitions with the recovered packet codecs.
6. Live-confirm the implemented introducer relay across two distinct NAT
   mappings; implement operation `4` only if live use establishes its result
   object.
7. Live-confirm the `0` -> `3` -> `2` classification sequence and complete a
   same-LAN/direct match before deploying introducer-assisted traversal.

The automated tests validate the recovered serializers and server behavior; they
do not replace the pending live RPCS3 gates.

## Legal and security

Do not distribute Activision or Sony binaries, publisher files, certificates,
private keys, credentials, production tickets, or copyrighted captures. Public
implementations may be studied for behavior and architecture, but code must not
be copied unless its license is deliberately accepted and complied with. The
server uses the MIT-licensed `github.com/cxmcc/tiger` package; required notices
for it and the Go runtime are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
