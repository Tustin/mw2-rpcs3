# Milestone handover: retail control plane through peer transport

Date: 2026-07-28

Target: MW2 PS3 `BLUS30377`, title update `1.14`, running on RPCS3/RPCN.

This milestone restores and validates the server-side path from a retail
authentication request through a usable matchmaking candidate, then documents
and implements the exact packet primitives required for the peer path. It does
not claim a completed live two-client match; that remains the next validation
milestone.

## Outcome

The implementation now covers:

1. dynamic retail authentication and ticket generation;
2. one-use LSG ticket consumption and encrypted LSG records;
3. the exact storage operation-8/operation-5 playlist fetch;
4. a retail-parser-valid minimal `playlists.info`;
5. service-5 create, update, delete, and find-sessions;
6. a shared, concurrent matchmaking directory with exact result objects;
7. public-address and NAT-classification UDP exchanges;
8. the current legacy introducer's exact relay behavior;
9. strict CommonAddr, QoS, NAT-traversal, and old-bdDTLS codecs; and
10. automated two-client flows using both synthetic encrypted LSG connections
    and the production TCP authentication path.

The screenshot remaining on “Fetching Playlists” is not evidence that the
playlist text is malformed. The current Linux deployment correctly advertises
the canonical LF fixture as 193 bytes; a Windows checkout can be 205 bytes due
to CRLF expansion. No live run has reached operation `5`. The server must
advertise the exact bytes it loads, and direct client control flow proves the
remaining handoff.

## Playlist resolution

### Exact operation-8 reply

```text
raw U8     reply message type = 1
typed U64  transaction
typed U32  error = 0
typed U8   operation = 8
typed U32  result count
repeat result count:
    typed U32  actual file byte size
    bdFileInfo
```

### Exact operation-5 reply

```text
raw U8     reply message type = 1
typed U64  transaction
typed U32  error = 0
typed U8   operation = 5
typed U32  destination-buffer size
bdFileInfo
typed Blob:
    typed U32  byte length
    raw file bytes
```

Operation `5` has no outer result count. The leading size is a
destination-buffer capacity hint; the nested Blob length is the authoritative
raw-byte count. The implementation canonically emits both as the actual payload
length. `bdFileInfo` is:

```text
typed U64    file ID
typed U32    value 1
typed U32    value 2
typed Bool   flag 1
typed Bool   flag 2
typed U64    value 3
typed String NUL-terminated filename
```

The decisive fetch trace is
`0x00322aa8..0x00322bfc -> 0x00322848 -> 0x003edf18`:

- filename getter `0x003ec8c0` returns `bdFileInfo + 0x28`;
- the client compares that string with exact `playlists.info`;
- only after equality, ID getter `0x003ec898` reads the `u64` at `+0x08`;
- operation `5` is started with only that ID; and
- application consumer `0x0030b1f0` accepts at most `0x20000` bytes and calls
  playlist parser `0x00258bf0`.

The neutral metadata values are not read in this transition. There is no
cache-version or timestamp gate in this two-stage fetch path.

The bundled fixture is 205 bytes, version 504, with one visible slot:

```text
playlist 0
gametype dm
entry mp_afghan,dm,100
minparty 1
maxparty 1
```

Static confidence:

- reply wire layouts: greater than 99%;
- exact filename-to-file-ID handoff: greater than 99%;
- fixture accepted as a visible, solo-selectable row: 95%;
- live RPCS3 download/application: not yet observed.

## Matchmaking resolution

Retail matchmaking is service `5`.

| Operation | Meaning | Status |
|---:|---|---|
| `1` | create | implemented; returns generated Blob[8] ID and Blob[16] key |
| `2` | update | implemented; retains generated ID/key |
| `3` | delete | implemented |
| `4` | find by ID | request known, result class/call site not proven; unsupported |
| `5` | find sessions | implemented with zero/nonempty exact results |

The seven operation-5 query values are now identified in wire order:

```text
q0  !xblive_rankedmatch
q1  raw selected playlist/game-mode ID
q2  netcode/protocol version
q3  owned map-pack flags
q4  playlist version
q5  required free public slots
q6  performance/skill value
```

Only the availability rule is implemented:

```text
host.openPublic >= query.requiredFreeSlots
```

The historical backend comparisons for `q0..q4` and `q6` are not in the client
binary. Equality, mask containment, playlist compatibility, or skill-distance
rules would be guesses, so they remain deliberately non-filtering.

Active hosts force operation `2` every 180 seconds. Dirty host changes are
coalesced for at least three seconds. The backend expiry duration is not
recoverable from the client, so the directory does not invent a TTL.

Emulator-only hardening policies are explicit: the directory is capped at 4096
records, update/delete are accepted only from the LSG connection that created
the record, and records are reclaimed when that connection closes. A separate
five-minute authenticated-LSG idle limit safely exceeds the proven 180-second
host refresh. The wire request has no explicit owner field, so these are not
presented as recovered historical principal or expiry behavior.

## Address discovery and traversal

The UDP listener implements:

| Request | Response | Proven behavior |
|---|---|---|
| exact `1e 02 00` | 9-byte `0x1f` | observed IPv4 and little-endian port |
| exact `14 02 00 00` | 15-byte `0x15` | reply from primary UDP listener |
| exact `14 02 00 03` / `02` | 15-byte `0x15` | reply from alternate UDP listener |
| exact 29-byte `0x0a`, version `>=2` | 29-byte `0x0b` | relay to embedded destination from primary listener |

The introducer relay was verified against the current legacy endpoint with two
independent UDP sockets. It preserves every byte except packet type, uses the
embedded destination IPv4/port, and does not validate the opaque identifier,
HMAC, or embedded source. That is current primary wire evidence, not recovered
server source. Untested rate limiting and historical deployment policy are not
claimed.

The relay is disabled by default. Set `MW2_NAT_RELAY_ENABLED=true` only in an
isolated/trusted lab: the exact protocol is an unauthenticated UDP forwarding
primitive whose embedded destination controls the server's send target.

CommonAddr is exactly 25 bytes: three local address slots, one public address,
and one NAT byte. Unused local slots use `00 ff 00 ff 00 00`. The traversal
identifier is the first four Tiger-192 bytes over the exact six-byte effective
endpoint.

## Peer protocol boundary

The central service returns the host's exact CommonAddr, Blob[8] ID, and
Blob[16] key. It does not answer QoS or act as the game host.

Recovered peer primitives include:

- QoS request `0x28`, 17 bytes;
- QoS reply `0x29`, 18-byte header plus data;
- NAT traversal `0x0a..0x0d`, 29 bytes;
- bdDTLS Init/InitAck/CookieEcho/CookieAck, 16/38/177/114 bytes;
- bdDTLS Error, 15 bytes; and
- bdDTLS Data, including HMAC, prefix transform, clear tail, sequence expansion,
  and the 32-packet replay window.

MW2 type-6 Data does not use the newer-title AES layout. Its authenticated
scope is:

```text
wire[0:6] || wire[16:end]
```

The first eight HMAC-SHA1 bytes are stored at `6..13`; the prefix-length field
at `14..15` is not authenticated but is structurally checked. The padded prefix
uses repeated Blob8 XOR and literal `0x01` padding. The tail remains clear.
Canonical output is capped at a `0x4ef`-byte reconstructed title packet and a
`0x504`-byte wire packet.

These codecs are intentionally isolated. The first title-message opcode and
gameplay dispatcher are not claimed without evidence.

## Release hardening

The milestone also closes deployment hazards found during the release audit:

- ordinary logs contain lengths, hashes, and decoded non-secret fields rather
  than raw RPCN tickets, session keys, decrypted payloads, or frame plaintext;
- raw packet capture remains separately opt-in and carries the existing
  credential-handling warning;
- the introducer relay is disabled by default;
- matchmaking update/delete are connection-owned;
- the matchmaking directory is bounded to 4096 records;
- closing an authenticated LSG connection reclaims its hosted records;
- the five-minute authenticated-LSG idle bound exceeds the 180-second host
  refresh cadence;
- native and container builds select Go 1.25.12, which contains the fixes
  required by the current Go vulnerability database; and
- third-party Go/Tiger notices ship in the repository and scratch image.

## Automated flow coverage

`internal/auth/retail_auth_full_flow_test.go` starts the actual TCP auth server
and uses two independent clients. It:

1. sends two retail-format auth requests;
2. decrypts and validates both dynamic game tickets;
3. validates the exact issued LSG ticket schemas;
4. consumes the issued tickets without pre-seeding or reading private server
   state;
5. rejects replay of both one-use tickets;
6. completes storage operations `8` and `5`;
7. creates a host session;
8. finds the host from the second connection;
9. verifies the exact candidate tuple; and
10. checks production counters.

The older encrypted two-client harness remains useful as a focused protocol
test. The production-path harness closes the prior gap where tests bypassed
real ticket issuance.

## Verification commands

The milestone is gated by:

```text
gofmt on all changed Go files
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
govulncheck ./...
git diff --check
docker build -t mw2-rpcs3:verify .
docker compose config
```

All listed gates passed on the milestone branch. Compose validation used
`MW2_NAT_ADVERTISED_IP=192.0.2.10`; the value is a documentation-only address,
not a deployment default.

The external playlist validators are also run against the bundled fixture.
No proprietary executable, PDB, packet capture, key, or credential is added to
the repository.

## Known boundaries

The following are intentionally not presented as solved:

- a fresh RPCS3 client downloading and applying operation `5`;
- a live two-account create/find/join/gameplay run;
- service-5 operation `4`, which has no recovered MW2 caller/result class;
- historical comparators for query fields other than free slots;
- exact backend stale-session expiry;
- historical owner/principal policy absent from the request bodies (the
  emulator uses connection ownership as a hardening policy);
- production introducer anti-abuse/rate-limit behavior;
- the first decrypted title opcode and full gameplay message state machine;
- host migration, stats persistence, leaderboards, anti-cheat, or relays beyond
  the proven introducer forwarding behavior.

## Next milestone

The next milestone is a sanitized live two-client RPCS3 trace:

1. confirm operation `8` completes with byte size `205`;
2. observe operation `5` using the advertised ID;
3. confirm the Public Playlists row appears;
4. capture host create and seeker find;
5. confirm CommonAddr and candidate ID/key byte-for-byte;
6. observe QoS, direct or introduced NAT traversal, and type-1..6 bdDTLS;
7. identify the first authenticated title message; and
8. complete one joined private match.

If local game assets are unavailable, the server and static work can continue,
but live completion cannot be honestly claimed. Preserve all captures outside
the repository until credentials and account material are removed.

## File map

- `internal/auth/raw_server.go`: auth/LSG TCP server and runtime dispatch
- `internal/auth/lsg_storage.go`: exact playlist storage requests/replies
- `internal/auth/lsg_matchmaking.go`: service-5 parser and replies
- `internal/auth/lsg_matchmaking_store.go`: shared retail session directory
- `internal/auth/retail_auth_full_flow_test.go`: production-path two-client test
- `internal/services/nat/server.go`: discovery, classification, and introducer
- `internal/peerproto`: CommonAddr, QoS, NAT traversal, and bdDTLS codecs
- `docs/demonware-storage-playlists.md`: storage proof
- `docs/demonware-matchmaking.md`: service-5 proof and confidence boundaries
- `docs/demonware-peer-qos.md`: QoS/traversal/introducer proof
- `docs/demonware-peer-dtls.md`: secure-association and Data proof
- `THIRD_PARTY_NOTICES.md`: Go runtime and Tiger redistribution notices
- `CURRENT_PROGRESS.md`: current authoritative status
