# MW2 (PS3) Demonware client ↔ server flow

Reconstructed from the externally supplied retail PS3 capture (XMB → Play
Online → PSN sign-in → Demonware auth → lobby data), cross-referenced with the
externally supplied `default_mp.elf` and the current server implementation in
`internal/auth/`. The proprietary capture and executable are local research
inputs and are not committed to this repository.

This is a multi-part document:

- **`demonware-flow.md`** (this file) — high-level connection map and phases.
- **`demonware-auth.md`** — the authentication service (TCP 3074, unencrypted).
- **`demonware-lsg.md`** — the LSG lobby-service connection (TCP 3074, 3DES).
- **`demonware-ip-discovery.md`** — separate public-address and NAT-classification
  UDP exchanges.
- **`demonware-peer-qos.md`** — post-find game-peer QoS and NAT-traversal
  datagrams.
- **`demonware-peer-dtls.md`** — the peer-only secure association after
  address resolution.
- **`demonware-next-steps.md`** — what is implemented vs. what blocks lobby entry.

## Connection map (from the capture)

The client (`192.168.0.199`) opens two TCP connections to Demonware auth hosts
on port **3074**, plus assorted PSN/CDN HTTPS traffic that is not part of
Demonware matchmaking.

| tcp.stream | Peer | Purpose | Bytes | Notes |
|-----------:|------|---------|------:|-------|
| 9  | `185.34.107.28:3074` | **Auth service** | 320 → 295 | One request, one response, connection closes |
| 11 | `185.34.107.69:3074` | **LSG lobby service** | 152 hello → 63 kB stream | Long-lived, 3DES-encrypted after hello |

Both endpoints speak the same length-prefixed Demonware framing but are
different services: stream 9 is the stateless authentication endpoint, stream 11
is the persistent Lobby Service Gateway (LSG). The game resolves them as
separate hostnames (see `DW_DNS_RESOLVING` / `DW_LOBBY_CONNECTING` in the ELF).

The capture also resolves `mw2-stun.us.demonware.net` and
`mw2-stun.eu.demonware.net` for separate UDP public-address and NAT-classification
exchanges. The exact `0x1e`/`0x1f` and v2 `0x14`/`0x15` paths are implemented
on primary `3074` plus alternate-source `3075`. The primary listener also
implements the independently wire-validated type-`0x0a` to type-`0x0b`
introducer relay. None of these are LSG traffic, and the central service does
not answer the game peers' QoS probes. The exact later peer packet formats are
recovered in `demonware-peer-qos.md`.

## Client-side state machine (ELF strings)

The MP executable drives connection through these observable states:

```
DW_DNS_RESOLVING
DW_DNS_NOT_RESOLVED
DW_REQUESTED_NP_TICKET      ← fetches PSN/NP ticket
DW_AUTHORIZING              ← stream 9 request in flight
DW_AUTHORIZING TIMED OUT
DW_AUTHORIZED (%d msecs)    ← stream 9 success parsed
DW_LOBBY_CONNECTING         ← stream 11 opens, hello sent
DW_LOBBY_CONNECTED          ← LSG hello ack + connection-ID exchanged
```

"Connecting to Matchmaking Server Complete." in the UI corresponds to reaching
`DW_LOBBY_CONNECTED`. It does **not** mean playlist/profile bootstrap finished.

## End-to-end phase order

1. **NP ticket** — client obtains a PSN/NP ticket (`DW_REQUESTED_NP_TICKET`).
   On RPCN this is an RPCN-issued ticket; the string `RPCN` appears in the
   authorization ticket blob and shifts the embedded LSG session-key offset
   (see `demonware-auth.md`).
2. **Authentication** (stream 9) — client sends a 320-byte authorization
   request carrying the NP/authorization ticket; server replies with a 295-byte
   success record containing the game ticket, the client session key, and the
   LSG ticket. Connection closes.
3. **LSG connect** (stream 11) — client opens a new connection and sends the
   unencrypted LSG hello (type 7) carrying game ID + the LSG ticket. Server
   replies with an unencrypted hello-ack containing a connection nonce.
   All subsequent records are 3DES-CBC encrypted with a SHA-1 HMAC.
4. **Address/NAT discovery** (UDP 3074/3075) — the client obtains its observed
   address and performs the recovered three-test NAT classification. This can
   overlap the persistent lobby bootstrap.
5. **Lobby bootstrap** (stream 11, encrypted) — the raw message type identifies
   each Demonware service, followed by storage, stats, bandwidth, and later
   matchmaking tasks. The connection ID was already returned in the
   unencrypted type-4 hello acknowledgement.
6. **Candidate QoS/traversal** (game-peer UDP) — after a nonempty service-5
   search result, the seeker probes the advertised host directly. This phase
   uses raw packet types `0x28`/`0x29` and `0x0a..0x0d`, not LSG task records.
7. **Peer DTLS/title traffic** (game-peer UDP) — the clients perform the
   recovered type-`1..4` secure-association handshake, then exchange
   authenticated type-`6` title data directly.

The exact byte layouts for phases 2–7 are in the sibling documents.
