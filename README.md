# Modern Warfare 2 RPCS3 Private-Match Emulator

A clean-room Go research backend for restoring private-match connectivity to **Call of Duty: Modern Warfare 2** on RPCS3.

## Current status

This repository now provides a safe, testable compatibility-server foundation:

- bounded binary framing and typed-buffer primitives;
- service/task dispatch with protocol-level error responses;
- experimental RPCN identity mapping and session tickets;
- independently authored static MOTD/playlist responses;
- concurrency-safe private-session creation, discovery, join, leave, heartbeat, and expiry;
- an experimental UDP observed-address endpoint;
- opt-in, bounded, redacted capture records and an offline inspector;
- health, readiness, and privacy-safe JSON metrics.

The authentication listener now reproduces the first verified retail exchange: BLUS30377 1.14 connects to `mw2-ps3-auth.mmp3.demonware.net` over TCP `3074`, sends a 304-byte request, receives the observed 11-byte rejection, and the server closes the connection. Successful authentication, post-authentication framing, cryptography, service IDs, and required publisher files remain unknown and must be established from user-owned runtime evidence. The lobby wire format remains an explicitly experimental envelope rather than pretending unverified details are authentic Demonware behavior.

## Scope

The first target is two RPCS3 clients running `BLUS30377` update `1.14`, signed into RPCN, joining one private match over a LAN or manually forwarded UDP. Public matchmaking, stats, progression, leaderboards, physical PS3 consoles, relays, anti-cheat, and host migration are out of scope.

RPCN remains responsible for PSN-like identity, friends, presence, invitations, NP tickets, and standard NP signaling. This service is intended to provide only the title-specific control plane proven necessary through capture. Gameplay should remain directly between clients.

## Build and test

Requirements: Go 1.25 or Docker.

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

Or with Docker Compose:

```bash
docker compose up --build
```

Default listeners:

- retail authentication TCP `3074`, verified from BLUS30377 1.14 capture;
- experimental post-authentication/lobby TCP `3075`, not yet verified;
- experimental observed-address UDP `3076`, not yet verified;
- health/metrics HTTP `8080`.

Only the initial authentication address and TCP port are currently verified MW2 behavior.

## Configuration

All configuration is environment-based:

- `MW2_AUTH_ADDR`, default `:3074`
- `MW2_LOBBY_ADDR`, default `:3075`
- `MW2_NAT_ADDR`, default `:3076`
- `MW2_HTTP_ADDR`, default `:8080`
- `MW2_LOG_LEVEL`, one of `debug`, `info`, `warn`, or `error`
- `MW2_MAX_FRAME_BYTES`, default 1 MiB, valid range 64 bytes to 16 MiB
- `MW2_READ_TIMEOUT`, default `30s`
- `MW2_WRITE_TIMEOUT`, default `10s`
- `MW2_SESSION_TTL`, default `2m`
- `MW2_CAPTURE_ENABLED`, default `false`
- `MW2_CAPTURE_DIR`, default `captures`
- `MW2_MOTD`, independently authored text returned by the experimental storage service

Endpoints:

- `GET /healthz`
- `GET /readyz`
- `GET /metrics`

## RPCS3/RPCN lab setup

1. Use a legally obtained `BLUS30377` installation updated to `1.14` on both clients.
2. Record the exact RPCS3 build/commit, firmware, patches, DLC inventory, and RPCN version.
3. Create separate RPCS3 profiles and RPCN accounts. Set Network Status to **Connected** and PSN Status to **RPCN**.
4. Start with both clients and the server on one LAN. Do not debug NAT and the title protocol simultaneously.
5. Enable focused RPCS3 logging for `sys_net`, `rpcn`, and signaling. Keep logs private until credentials and tokens are removed.
6. Capture DNS and network metadata with Wireshark or tcpdump on the host interface and loopback where applicable.
7. Inventory each hostname, destination, port, transport, TLS SNI, connection order, packet length, retry, timeout, and menu transition.
8. Add RPCS3 IP/Host Switch entries one hostname at a time after the original hostname is observed. Do not use a wildcard initially. The exact mapping syntax and hostnames must come from the current RPCS3 documentation and the captured title behavior.
9. If redirection reaches the server but TLS or application validation fails, stop and record the evidence. Do not disable security checks server-side or claim success; a narrowly scoped RPCS3 game patch requires separate review.

RPCN commonly uses TCP `31313`, its UDP endpoint helper uses `3657`, and RPCS3 peer signaling commonly uses UDP `3658`. These RPCN values are separate from unknown MW2 publisher endpoints.

## Capture workflow

Raw capture is disabled by default because packets may contain account material.

```bash
MW2_CAPTURE_ENABLED=true MW2_CAPTURE_DIR=./captures go run ./cmd/mw2-server
```

Capture records are JSON Lines with timestamp, listener, direction, remote address, original length, SHA-256, and a bounded hexadecimal payload. Common textual credential labels are redacted, but binary secrets cannot be identified reliably. Review every record manually before sharing or committing it. `captures/*` is ignored by Git.

Inspect a raw stream encoded with this project's experimental frame envelope:

```bash
go run ./cmd/mw2-inspect ./path/to/stream.bin
```

Inspect a server capture file:

```bash
go run ./cmd/mw2-inspect -jsonl ./captures/capture-YYYYMMDD.jsonl
```

The inspector failing to decode a retail packet is expected until the actual framing is discovered. Preserve original PCAPs outside the repository and add only sanitized, legally shareable fixtures to `testdata/`.

## Verified retail authentication exchange

RPCS3 host redirection should map:

```text
mw2-ps3-auth.mmp3.demonware.net=<SERVER_IP>
```

The TCP `3074` listener reads exactly 303 bytes, logs a SHA-256 and bounded printable-field summary, optionally records the raw request when capture is enabled, sends the observed rejection below, and closes the connection:

```text
07 00 00 00 00 13 C4 05 00 00 00
```

The retail client closes the auth socket and retries after receiving this response. Replaying it verifies the redirected transport path, but does not authorize the client or advance it to the lobby endpoint.

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

1. Identify all publisher endpoints and TLS behavior.
2. Decode the first client request from BLUS30377 1.14.
3. Reach the multiplayer menu and remain authenticated for ten minutes.
4. Register a host private session.
5. Resolve and join from a second RPCS3 client on the same LAN.
6. Confirm gameplay packets flow directly between clients and complete a match.
7. Only then test manual UDP forwarding, UPnP, and two ordinary NATs.

The repository's automated tests validate the research scaffold, not retail-game compatibility.

## Legal and security

Do not distribute Activision or Sony binaries, publisher files, certificates, private keys, credentials, production tickets, or copyrighted captures. Public implementations may be studied for behavior and architecture, but code must not be copied unless its license is deliberately accepted and complied with. This project currently uses only the Go standard library and independently authored code/data.
