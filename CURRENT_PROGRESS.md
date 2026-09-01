# Current status of MW2 Demonware server emulation

_Last updated: 2026-09-01 after tracing the accepted-QoS candidate owner and
post-filter selector. The 80-byte entries are party connection candidates owned
by the session/party object, not secure-association records. `+0x44` is the total
QoS latency/value written by `CommitCandidateQoSResult` (`0x000cd998`), `+0x48`
is its probe count, and `+0x4C` is the normalized selection metric.
`InvalidateCandidatesWithoutQoS` (`0x000cff28`) only deactivates entries whose
`+0x44` remains `-1`. The later independent party-state path
`SelectJoinablePartyCandidate` (`0x000d5750`) chooses the lowest `+0x4C` survivor,
probes it through `ProbeSelectedPartyCandidate` (`0x000d2468`), copies its tuple
into party join state through `CopySelectedCandidateToPartyJoinState`
(`0x000d26e0`), and calls `sub_CED10`. This matches World at War's
QoS-callback/filter -> best-host selector -> party/session copy -> network-start
pipeline. The supplied `qos.bin` therefore identifies the failure earlier: the
sole candidate never receives its QoS metric before cleanup. The next diagnostic
should trace the ID mapping at `sub_CB538` (`0x000cb538`) and the following
`CommitCandidateQoSResult` call at `0x002fa300`, recording the completed QoS
session/security ID, mapped candidate index, candidate active byte, and `+0x44`
before and after the commit. Do not instrument `sub_2FD758` or rerun the broad
accepted-QoS dump first._

## Executive summary

The project gets MW2 on RPCS3 through dynamic Demonware authentication, the
encrypted Lobby Service Gateway (LSG) handshake, storage, and playlist loading.
The retail `playlists.info` has been retrieved, the storage flow works live, and
the game client accepts the emulated server's playlist. Two live clients now
find one another and complete direct traversal and QoS. Corrected performance
replies are accepted, and telemetry proves both clients pass the type-1 QoS gate.
The latest custom-server capture shows both clients receiving usable identities,
exchanging direct traversal and QoS, and accepting service-17 performance replies,
but the first public find returned before the reciprocal advertisement existed.
This produced mismatched initial directory snapshots and symmetric peer testing,
unlike retail, where both 289-byte two-result replies arrive before traversal.
The 2026-08-03 physical-PS3/RPCS3 retest confirmed that delaying the first
self-only public find produced the same two-session snapshot for both clients.
Their serialized result arrays were byte-identical after the transaction ID and
ordered by advertisement creation: RPCS3 first, physical PS3 second for both
requesters. That blocking server-side delay has now been removed: operation `5`
returns the current creation-ordered snapshot immediately, so the LSG reader can
continue servicing the connection without an artificial five-second pause. An
opt-in `MW2_MATCHMAKING_SUPPRESS_SELF_ONLY=true` compatibility flag can instead
turn only a requester-owned single-result snapshot into an immediate successful
zero-result reply. The 2026-09-01 live test proved this behavior but did not
change the outcome: both clients still reached reciprocal two-result finds,
direct traversal/QoS, and accepted performance reports without joining. Default
behavior remains unchanged. The next task is the already-isolated downstream
post-QoS client-local promotion and secure-association transition.

Static analysis of `default_mp.elf` has now corrected the storage reply layouts:

- every typed task reply begins with a raw one-bit type-checking marker;
- operation `8` is an outer result count followed by a typed file size and
  `bdFileInfo` for each result;
- operation `5` has no outer result count on the wire. It begins with a typed
  destination-buffer size, followed by `bdFileInfo` and the typed blob.
- `messageoftheday.info` is fetched through the same list/get state machine
  before `playlists.info`; both must be present in the publisher directory.

The vanilla and modified-client traces use identical operation-8 requests and
receive identical replies, but only the modified TU0-derived client advances to
operation 5. The reason is executable version, not the dump hook: the loaded IDA
ELF is the TU0 build and requests `playlists.info`, while RPCS3 boots the
9,038,448-byte NPDRM title-update SELF from `/dev_hdd0/game/BLUS30377`. After
decrypting that exact SELF with content ID
`UP0002-BLUS30377_00-MW2P000000000014`, its publisher state table proves the
exact playlist filename is `playlists.patch3`. The server now advertises and
serves both playlist names from the same bytes, with distinct stable IDs.

A separate sensitive trace captures five service-10 operation-5 fetches. They
were previously misreported as unknown tasks because the parser expected the
`u64` file ID immediately after the operation and encountered type tag `3`.
Builder `0x003edf18` proves the retail request writes typed `u8(0)` before typed
`u64(file ID)`. The parser, tests, telemetry, and packet codec consume that
selector.

The Go serializers and focused tests have been updated to those layouts. Direct
tracing of the retail playlist parser and Public Playlists feeder confirms that
the bundled file is not merely syntactically valid: playlist ID `0` is visible,
the `mp_afghan,dm,100` entry is accepted, and party bounds `1/1` permit a solo
player. The operation-8 completion loop is also now proven: it selects exact
filename `playlists.info`, copies only its `u64` ID, starts operation `5`, and
passes the downloaded buffer (up to `0x20000` bytes) directly to the playlist
parser. The same filename/opaque-ID handoff serves a bounded plain-text MOTD
first. Neutral metadata fields are not a fetch gate. Live RPCS3 testing has now
confirmed that storage completes and the client accepts the served playlist.

The service-5 audit recovered operations `1` create, `2` update, `3` delete,
`4` find by ID, and `5` find sessions. The server now implements the
statically proven create/update/delete/find lifecycle with a process-wide
thread-safe directory shared by retail LSG connections, generated session
ID/key material, and exact zero/nonempty find-result serializers. Operation
`4` and the retail backend's seven-field search-filter policy remain
unimplemented because their exact semantics are below the requested confidence
threshold.

The latest preserved RPCS3 trace did not reach either publisher-file parser.
It repeatedly received service-18 error `108`, never sent the five UDP
bandwidth uploads or the finalize request, and therefore never issued storage
operation `5`. Current source and focused tests instead produce the recovered
51-byte request success and 29-byte finalize success, and current logs add
`bandwidth_phase` and `endpoint`; those fields are absent from the preserved
trace. This is strong evidence that the captured run used a stale/pre-fix
binary. No additional playlist serializer change is justified until a clean
current-source deployment completes the bandwidth prerequisite.

A newer fresh server diagnostic did complete the current bandwidth exchange
but repeatedly requested unfiltered storage operation `8` after receiving a
three-entry directory. The third entry, `mp/mappack.info`, had no direct MW2
ELF or retail-capture proof and was absent from the previously recovered
two-file state machine. It has been removed. The operation-8 and operation-5
wire serializers were left unchanged because direct consumer analysis and
golden tests continue to establish their existing field order. A subsequent
live test showed no client progress and clarified that visible transaction IDs
`0,0` were generated by an unsupported server-side compatibility experiment,
not observed in a retail reply. That experiment has been removed: every
separate storage task again receives its own monotonically increasing
transaction ID.

The ELF and packet capture also establish the UDP public-address and v2 NAT
classification exchanges. Exact `1e 02 00` requests receive the nine-byte
observed-address reply. Exact `14 02 00 command` requests support commands `0`,
`3`, and `2`; command `0` replies from primary UDP `3074`, while `3` and `2`
reply from alternate UDP `3075`. The exact 15-byte reply advertises the
alternate/source-check server IPv4 paired with the primary query port. NAT
QoS is not a central discovery reply: its exact peer packet codec and the
following peer-DTLS flow are recovered from the ELF. The current legacy
introducer was independently probed and confirms strict 29-byte
embedded-destination routing with only `0x0a` -> `0x0b` mutation from primary
UDP `3074`; that narrow relay is implemented behind a disabled-by-default,
trusted-lab flag. Live two-client confirmation and untested production
anti-abuse policy remain unresolved.

## Current end-to-end state

| Phase                               | Status                                                                                     | Evidence / notes                                                                                                                                                                                                                                                |
| ----------------------------------- | ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Listener startup                    | Working                                                                                    | Auth/LSG TCP and primary discovery UDP coexist on `3074`; alternate-source UDP `3075`, experimental lobby, and HTTP listeners also start.                                                                                                                       |
| Dynamic authentication              | Working in prior live runs                                                                 | A fresh session key, game ticket, and LSG ticket are generated per connection.                                                                                                                                                                                  |
| RPCN key extraction                 | Working in prior live runs                                                                 | The LSG key is found relative to the `RPCN` marker rather than a brittle absolute offset.                                                                                                                                                                       |
| Encrypted retail LSG                | Working in prior live runs                                                                 | Client requests decrypt and validate; replies use the observed 3DES-CBC record framing.                                                                                                                                                                         |
| Storage operation `8`               | Working live                                                                               | Returns leading type-checking bit `1`, then the proven publisher results `messageoftheday.info`, TU0 `playlists.info`, and title-update `playlists.patch3`, each with actual byte size and `bdFileInfo`. A speculative `mp/mappack.info` entry remains removed. |
| Storage operation `7`               | Implemented                                                                                | Returns a successful empty outer result count.                                                                                                                                                                                                                  |
| Storage operation `5`               | Working live                                                                               | Consumes typed `u8(0)` before the advertised opaque ID, then returns actual buffer size, matching `bdFileInfo`, and the raw typed blob. The client accepts the served playlist.                                                                                 |
| MOTD prerequisite                   | Implemented                                                                                | Two binary state initializers request `messageoftheday.info`; the consumer accepts at most `0x100` bytes of plain text. `MW2_MOTD` overrides the built-in welcome text.                                                                                         |
| Bundled `playlists.info`            | Retail-parser valid; 95% confidence                                                        | ID `0` is feeder-visible, alias/script `dm` resolves, the weight-100 entry counts, and solo bounds pass selection.                                                                                                                                              |
| Docker playlist packaging           | Fixed in the working tree                                                                  | The final image copies the fixture to `/playlists.info` and sets `MW2_PLAYLISTS_FILE`.                                                                                                                                                                          |
| Stats                               | Placeholder only                                                                           | The observed retail request is service `4`, operation `4`; the server currently returns an empty success.                                                                                                                                                       |
| Groups                              | Set/clear serializers recovered; matchmaking performance call was previously misclassified | Service `17`, operation `2` in the live matchmaking path is `bdMatchMaking::getPerformanceValues`, not set-groups. The actual group serializers remain identified at `0x003e4758` and `0x003e4638`.                                                             |
| Bandwidth                           | Two-phase bootstrap working live                                                           | Service `18/1` returns the exact 51-byte request result, accepts five 512-byte UDP uploads on the primary NAT socket, then returns the 29-byte finalize result. The current two-client run completed this phase on both clients.                                |
| Retail matchmaking op `5`           | Working live                                                                               | Both clients repeatedly receive the other client's candidate. The recovered unranked flag correctly selects private slots; nonzero uses private slots and zero uses public slots. Unknown retail comparisons are not guessed.                                   |
| Retail matchmaking lifecycle        | Working through candidate QoS and performance/session update; lobby handoff unresolved     | Two live clients create/find candidates, complete direct NAT/QoS, accept one performance result, and update their sessions from private `8/0` to `7/1`. They then restart searching rather than beginning peer DTLS.                                            |
| UDP public-address/NAT discovery    | Working live                                                                               | Exact v2 public-address and NAT-classification exchanges complete, including primary/alternate-source replies.                                                                                                                                                  |
| Peer QoS packet codec               | Working live                                                                               | Live clients exchange 17-byte `0x28` requests and 18-byte zero-payload `0x29` replies. All multibyte values are little-endian; the reply data length is a little-endian `u32`.                                                                                  |
| Peer NAT traversal and introducer   | Direct `0x0d`/`0x0c` traversal working live; legacy `0x0a` relay remains safety-gated      | Both clients exchange exact 29-byte type-`0x0d` requests and type-`0x0c` acknowledgements over LAN and the advertised external route. The trusted-lab introducer relay still accepts only strict type `0x0a` packets and changes only the type to `0x0b`.       |
| Peer DTLS codec                     | Recovered directly from the ELF; not reached live                                          | No peer-DTLS packet follows the successful traversal/QoS/performance sequence. Canonical Init/InitAck/CookieEcho/CookieAck/Error packets remain 16/38/177/114/15 bytes.                                                                                         |
| Playlist parsing / lobby population | Playlist accepted; lobby population unresolved                                             | Both clients select playlist `1`, advertise sessions, and search successfully, but return to candidate search after QoS instead of joining/populating a shared lobby.                                                                                           |
| Runtime discovery telemetry         | Corrected in the working tree                                                              | Packed operation IDs are decoded before logging; unsupported service/operation pairs are explicitly warned while still receiving an error reply.                                                                                                                |

Operation-8 request handling honors the version-aware publisher directory's
exact filename filter and pagination boundaries. Operation-5 requests contain a typed
zero selector before the file ID and must include the recovered zero five-bit
terminator.

## Established protocol findings

### Authentication and LSG transport

- Auth and retail LSG are separate TCP connections on port `3074`.
- The auth response is generated dynamically and includes an encrypted game
  ticket, client/session data, and an LSG ticket.
- The server keeps a one-use mapping from the issued LSG ticket to the 24-byte
  3DES session key.
- Normal encrypted LSG records use a little-endian length, encrypted flag,
  32-bit IV seed, Tiger-derived IV, and 3DES-CBC.
- Client request HMAC validation succeeds with the dynamically recovered RPCN
  key.
- After the hello acknowledgement, the encrypted raw message type is the
  service ID. Observed `0x12` is bandwidth service `18`, whose payload begins
  with an untyped raw operation byte.
- Reply message type `1` is the normal retail task-reply path.
- Bandwidth service `18` is the special reply-type-`5` path. The first
  success body is transaction `u64`, success byte, seven `u32` parameters,
  `u16` UDP port, IPv4, and an eight-byte token. Its finalize success body is
  transaction `u64`, success byte, and five `u32` result fields.

### UDP public-address and NAT discovery

- The capture resolves `mw2-stun.us.demonware.net` and
  `mw2-stun.eu.demonware.net`; both use UDP port `3074`.
- A version-2 request is exactly `1e 02 00`: type `0x1e` plus little-endian
  protocol version `2`.
- The exact reply is `1f 02 00`, four observed IPv4 octets, then the observed
  UDP source port as a little-endian `u16`.
- Captured `1f 02 00 18 d8 a2 6f 02 0c` replies confirm both the nine-byte
  layout and port `3074` (`02 0c` little-endian).
- Exact four-byte `14 02 00 command` requests accept commands `0`, `3`, and
  `2`. Command `0` replies from primary UDP `3074`; commands `3` and `2` reply
  from alternate UDP `3075`.
- Every accepted command receives the exact 15-byte `0x15` reply containing the
  observed client IPv4/port and the advertised alternate/source-check server
  IPv4 paired with the primary query port.
- QoS and peer direct traversal remain separate from discovery. The host game
  answers QoS. The same primary UDP listener handles the independently proven
  introducer case: strict 29-byte type `0x0a`, version `>=2`, embedded
  destination, and only `0x0a` -> `0x0b` mutation.

### Typed storage encoding

MW2 storage uses the LSB-first, bit-packed typed serializer. Tags and values are
not byte-aligned. The common successful reply prefix is:

```text
raw u8   message type = 1
raw bit  type-checking-present = 1
typed u64 transaction ID
typed u32 error code = 0
typed u8  operation ID
```

The message dispatcher constructs a type-checked `bdBitBuffer` at `0x003d2be8`
and consumes that first bit through `0x003d2810`. It is not optional padding.
Omitting it consumes the first typed tag's low bit and misaligns the complete
reply.

Operation `8` then contains:

```text
typed u32 result count = N
repeat N times:
    typed u32 file size
    bdFileInfo
```

The retail dispatcher at `0x003ecf18` reads the outer count. The operation-8
result handler at `0x003eb4a8` reads a file size for every result, deserializes
the metadata at `0x003eca78`, and stores the size in the resulting object.

Operation `5` then contains:

```text
typed u32 destination-buffer size
bdFileInfo
typed blob:
    typed u32 byte length
    raw bytes
```

For operation `5`, `0x003ecf18` supplies an implicit result count of one to
handler `0x003ea690`; it does not read an outer count from the wire. The handler
uses the first typed `u32` as a destination-buffer capacity hint before
deserializing the metadata and blob. The nested blob length is the authoritative
raw-byte count. This implementation canonically emits both values equal to the
number of raw bytes sent.

`bdFileInfo` is consumed in this exact order:

```text
typed u64 file ID
typed u32 value 1
typed u32 value 2
typed bool flag 1
typed bool flag 2
typed u64 value 3
typed string filename
```

The filename is tag `16`, followed by raw 8-bit characters and one NUL byte. It
has no length prefix. The current `writeMW2FileInfo` order and `writeString`
encoding match the retail parser.

## Storage and playlist implementation

The advertised publisher file uses:

- file ID `0x1122334455667788`;
- filename `playlists.info`;
- the actual loaded byte length in both the operation-8 metadata wrapper and
  operation-5 buffer-size field;
- neutral zero values for the other currently unused metadata fields.

The exact operation-8 completion loop at `0x00322aa8..0x00322bfc` compares the
result filename with `playlists.info`, reads the `u64` ID only after equality,
and starts operation `5` with that ID. It does not inspect the neutral metadata
fields or perform a local cache/version comparison. Consumer `0x0030b1f0`
accepts at most `0x20000` bytes and calls playlist parser `0x00258bf0` with the
downloaded buffer.

`playlists.info` is loaded from `MW2_PLAYLISTS_FILE`, then the runtime working
directory fallbacks. Empty files and files larger than `0x20000` are rejected.
The final Docker image now copies the fixture to `/playlists.info` and points the
environment variable at that path.

The bundled fixture passes the structural validator:

```text
version=504
gametypes=1
playlists=1
entries=1
bytes=<actual loaded byte length>
```

Retail parser control flow further establishes:

- playlist IDs `0..23` are accepted;
- feeder enumeration starts at slot `0` and skips only empty slots;
- a map entry counts only after its declared gametype resolves and its weight
  is positive;
- `mp_afghan,dm,100` meets those conditions; and
- party size one satisfies `minparty 1` / `maxparty 1`.

This establishes a visible, selectable minimal playlist document. It does not
establish that RPCS3 has downloaded or applied it.

## Retail matchmaking implementation

MW2 uses retail service `5`:

| Operation | Meaning            | Current server behavior                                                      |
| --------: | ------------------ | ---------------------------------------------------------------------------- |
|       `1` | create session     | stores exact host object; returns generated Blob[8] ID and Blob[16] key      |
|       `2` | update session     | replaces mutable object fields by embedded session ID while retaining ID/key |
|       `3` | delete session     | removes the record by Blob[8] session ID                                     |
|       `4` | find by session ID | exact request parser recovered; unsupported                                  |
|       `5` | find sessions      | exact type-2/max-50 query validated; returns capped zero/nonempty results    |

Operation `5` contains typed `u8(0)`, typed `i32` query type `2`, typed `i32`
maximum `50`, seven live positional `i32` values, two raw zero octets, and the
universal five-bit terminator. The query constructor starts with six
`INT_MAX` values and a final zero, but `0x00319e60` overwrites all seven before
the retail request is sent. Its successful zero-result reply is:

```text
typed u64 transaction
typed u32 error = 0
typed u8  operation = 5
typed u32 result count = 0
```

The result template at `0x004ef168` accepts zero without parsing an element.
For each nonempty result, parser `0x00325c38` requires the stored base object
plus all nine title-specific I32 values. The seven request fields are now
recovered as unranked flag, selected playlist/game-mode ID, netcode version,
owned map-pack flags, playlist version, required free slots, and
performance. The directory uses the recovered unranked flag to select the slot pool:
nonzero requires `openPrivate >= requiredFreeSlots`, while zero requires
`openPublic >= requiredFreeSlots`. Newly created records are now hidden from
operation `5` until their first successful owner operation-`2` refresh, matching
the client lifecycle in which create assigns the generated identity and update
publishes the complete advertisement. This removes the create/find race that let
a requester observe an incomplete peer before that peer's first refresh. A
later successful update replaces the mutable object without changing readiness.
This is confirmed by the latest two-client
trace: both searches carried `unranked=1`, both hosts advertised private slots,
and the public-only filter incorrectly returned zero. The successful retail
two-PS3 capture disproves equality filters for game mode, netcode, playlist
version, and performance. Map-pack comparison remains unproven; only game type,
slot pool, and free slots are currently enforced. Full schemas and confidence
boundaries are in
`docs/demonware-matchmaking.md`.

An active host forces operation `2` every 180 seconds. Dirty create/join/leave
state is coalesced for at least three seconds, and an update failure re-dirties
the active record. Normal teardown attempts operation `3`, but a failed delete
is not retried. The client does not reveal the backend expiry duration or an
explicit owner field in these request bodies, so the implementation does not
invent a time-based TTL. As explicit emulator hardening, records are capped at
4096, only the creating LSG connection may update/delete them, and all records
owned by that connection are reclaimed when it closes. The authenticated LSG
idle limit is five minutes, safely beyond the proven 180-second host refresh.
These are not claimed as recovered historical ownership or expiry rules.

## Prior live evidence and its limits

The 2026-07-27 live run remains useful for transport evidence:

1. RPCS3 authenticated with a fresh session key and LSG ticket.
2. It completed the LSG hello exchange.
3. Encrypted service requests decrypted successfully.
4. It issued repeated storage operation-8 requests and an owner-list request.
5. The connection remained alive and later issued a service-4 request.

That run serialized two `u32` values after operation `8` as `1, 1`. Static
analysis now identifies those as result count `1` and an incorrect file size of
`1`, not `numResults` and `totalNumResults`. The run therefore proves that the
two typed fields avoided the earlier immediate type mismatch, but it does not
prove that the storage task completed successfully. No operation `5` was
captured.

The service-4 request was previously logged as operation `7` because the generic
task parser treated packed bytes as byte-aligned. Decoding the observed packed
payload correctly identifies stats service `4`, operation `4`.

## Service boundaries

- Storage is retail service `10`.
- Stats is retail service `4`; only an empty operation-4 placeholder exists.
- Groups is retail service `17`; typed operation `2` set-groups is implemented as
  an empty success, while operation `3` clear-groups remains unimplemented.
- Retail matchmaking is service `5`; create/update/delete and zero/nonempty
  operation-5 search are implemented from direct static evidence.
- The custom session directory on the experimental listener is not the retail
  service-5 protocol and does not demonstrate MW2 matchmaking compatibility.
- Exact service-5 create/update/delete/find request layouts, operation-1
  ID/key results, mutation replies, and nonempty result objects are recovered.
  Operation `4` remains unimplemented. All seven op-5 query meanings are
  recovered; only the free-slot comparison is implementation-safe because the
  other historical backend comparators are not present in the client.
- UDP public-address and NAT classification are separate, implemented packet
  exchanges. The later peer QoS and NAT-traversal codecs are also recovered.
  The current legacy introducer's narrow relay behavior is live-observed and
  implemented, but no complete two-client RPCS3 run has exercised it yet.
- The unused operation-4 builder has no MW2 call site. Its count-bearing reply
  envelope is known, but the caller-selected found-record class and not-found
  policy are not; leaving it unsupported is safer than importing a
  cross-version guess.
- A nonempty operation-5 completion enters peer QoS directly using the echoed
  common address. No central service-5 join task is missing between search and
  peer traffic.

The "Connecting to Matchmaking Server Complete." message means the client
reached its connected LSG state. It does not prove playlist loading, profile or
rank initialization, retail matchmaking, lobby population, or peer traffic.

## Verification status

Static proof:

- `0x003ecf18` establishes the operation-specific outer-count behavior.
- `0x003eb4a8` establishes operation-8 result count -> file size ->
  `bdFileInfo`.
- `0x003ea690` and `0x003ec290` establish operation-5 buffer allocation from
  the leading size.
- `0x003ec558` establishes `bdFileInfo` followed by tag-19 blob parsing.
- `0x003eca78` establishes the seven metadata fields and NUL-terminated string.
- `0x00322aa8..0x00322bfc`, `0x00322848`, and getters `0x003ec8c0` /
  `0x003ec898` establish exact filename selection and file-ID-only operation-5
  handoff.
- `0x003e16a0`, `0x003de268`, `0x00325850`, and `0x00319ef8..0x00319f10`
  establish the matchmaking operation-5 layout and its seven live values.
- `0x003253c0` establishes that operations 1 and 2 include nine title-specific
  I32s after the base matchmaking object.
- `0x003e1840` establishes its reply header and single result count.
- `0x004ef168` establishes that zero operation-5 results are valid.
- `0x00424fd0` establishes the exact v2 `0x1e` public-address request.
- `0x004259a0` / `0x004259d0` establish the exact v2 `0x14` request and command
  byte; `0x004263c0` and `0x003d4da8` establish the 15-byte `0x15` result.
- `0x0042c548` / `0x0042c740` establish the 17-byte peer QoS request, while
  `0x0042bb70` / `0x0042c0d0` establish the 18-byte-plus-data reply.
- `0x0044b290` / `0x0044b4c0` establish the 29-byte NAT-traversal packet;
  `0x00442848` establishes its 28-byte-secret HMAC input and 10-byte output.
- `0x0043d6d8` establishes the peer-DTLS type-`1..6` dispatcher;
  `0x00441298`, `0x00442528`, `0x0043ed30`, and `0x0043e828` establish the
  canonical Init, InitAck, CookieEcho, and CookieAck layouts.
- `0x00440b00` / `0x004409c0` / `0x004408b0` establish the 15-byte type-5
  Error packet. `0x0043f9f0` and `0x00440200` establish type-6 HMAC scope,
  prefix padding/XOR, clear tail, and receive ordering; `0x00438c20`
  establishes verification-tag and replay enforcement.
- The supplied Ghosts PDB and OpenIW8 source independently identify the client
  type-only `0x0a` -> `0x0b` -> `0x0c` trust boundary. A controlled live probe
  of the current legacy endpoint proves strict 29-byte embedded-destination
  routing with only `0x0a` -> `0x0b` mutation; no server source was found.
- `0x002583c8`, `0x00259fa0`, and `0x00259d64..0x00259e88` establish
  playlist-slot-0 visibility and positive-entry counting.

Repository verification:

- focused Go tests assert the corrected operation-8 and operation-5 layouts;
- storage/full-flow/logging tests assert that the unfiltered publisher
  directory contains `messageoftheday.info`, TU0 `playlists.info`, and
  title-update `playlists.patch3`, with no speculative mappack result;
- focused Go tests also assert that the captured RPCN service-18 request reaches
  the raw handler, receives reply type `5` with the exact request/finalize
  success bodies, and that only exact 512-byte sequence-`0..4` UDP uploads are
  accepted;
- matchmaking tests assert exact create/update/delete/find golden vectors,
  nonempty result decoding, an encrypted two-client storage-to-candidate
  lifecycle, deterministic capping, deep-copy behavior, and concurrency safety;
- a production-path harness starts the real auth TCP server, authenticates two
  retail requests, validates both dynamic ticket schemas, consumes the issued
  one-use LSG tickets, rejects replay, and runs storage through matchmaking;
- the playlist validator accepts the bundled fixture bytes and retail
  feeder/parser analysis confirms its runtime semantics;
- UDP golden and localhost integration tests verify both discovery serializers
  and that commands `3`/`2` actually originate from the alternate source port;
- introducer golden/integration tests verify strict framing, version handling,
  embedded-destination routing, primary-listener source, and that only the
  type byte changes;
- Docker packaging now includes the fixture.

## Completed live storage verification

The retail `playlists.info` was retrieved successfully. The emulator's storage
flow now completes live, and the game client accepts the served playlist.

## Current task: matchmaking lobby

The retail Find Match sequence has now been compared with the preserved
one-client RPCS3 trace and the latest simultaneous physical-PS3/RPCS3 trace. The
preserved trace reaches storage op `5`, creates a service-5 session, sends the
exact operation-5 query, accepts repeated zero-result replies, updates the
session, and deletes it. Its first divergence from the retail ingame trace is
after directory lookup: retail sends a candidate-directed type-`0x28` QoS
probe, while the emulated run has no eligible candidate because its hosted
record advertises `openPublic = 0` and `openPrivate = 8` against
`requiredFreeSlots = 1`.

The latest two-client trace exposed an earlier playlist-side regression. Both
clients selected playlist `1`, created and refreshed private service-5 sessions,
but neither sent operation `5`. Static analysis confirms that
`party_minplayers = 1` makes a one-player party immediately satisfy the
playlist and returns before the `dwFindSessions` call. The fixture now uses
`party_minplayers = 2`, the minimal value that makes each solo client enter the
public-search path. `maxparty = 1`, `party_maxplayers = 8`, and
`party_matchedplayercount = 1` are not this gate.

The simultaneous RPCS3/physical-PS3 run supersedes the earlier service-17
classification. Both clients received two service-5 candidates, displayed one
potential game after excluding their own session, and completed direct peer QoS.
Immediately afterward each sent service `17`, operation `2`; the old handler
misidentified this as `bdGroup::setGroups` and returned success with zero result
objects. Both clients then reported `DW fetch performance values error 1024` and
deleted their sessions.

The request is now identified as `bdMatchMaking::getPerformanceValues`. The live
body contains operation `2`, a typed U32 performance type (`0` in every observed
request), and one or more typed U64 entity IDs. It does not carry an entity
count. The trailing repeated bytes are only 3DES padding. Four requests from
both clients decode identically apart from the entity ID.

The earlier handler incorrectly treated the performance type as a count. Since
it is zero, every reply was a successful task with zero result objects. This
removed the popup but did not provide a `bdPerformanceValue` to candidate
selection. The symbol-rich Ghosts PDB confirms the method signature accepts an
entity-ID array, count, a separate U32 argument, and `bdPerformanceValue*`.
Initial response work used the newer title's U64/I64 result layout, but the MW2
ELF analysis below supersedes that assumption. The parser correctly consumes the
U32 performance type and all remaining typed U64 entity IDs. A captured live
request is covered by a golden test.

Further MW2 client analysis on 2026-07-30 exposed a reply-framing error in that
correction. The generic remote-task layer consumes one typed U32 result count,
then `bdMatchMakingReadPerformanceValuesTaskResult` begins directly with the
first result object. The server was writing the count twice, so the callback saw
the second U32 count where it required result data. The success reply now writes
exactly one result count. Malformed operation-2 requests also now use the same
bit-packed, type-checked reply framing rather than the older byte-aligned generic
serializer. Unit tests independently decode both layouts. A live two-client test
is still required.

The absence of `DW fetch performance values error 1024` in the latest run only
proved that an empty success task no longer triggered the status popup. It did
not prove the client received a usable performance record. That run logged
`Fetched performance value 0 for b804d13e5ee3dafa` followed by `Unable to
retreive performance value`, then issued another operation-2 request.

Completed MW2-specific IDA analysis on 2026-07-31 now establishes the complete
result-object wire layout. `bdMatchMakingReadPerformanceValuesTaskResult` reads a
raw, untyped big-endian U32 status first. Status `0` is the success path; only
then does it read the typed U64 entity ID followed by another raw, untyped
big-endian U32 performance value. The consumer copies that final value directly
into the candidate's 32-bit performance field, and zero is rejected by the
client as unusable. This supersedes the earlier Ghosts-derived typed-I64
assumption. The server now emits `raw status 0`, `typed U64 entity ID`, and `raw
performance 1` per result. A subsequent codec audit found that the generic raw
U32 writer serialized those two raw fields least-significant byte first, while
the recovered MW2 reader explicitly reverses four wire bytes into host order.
Status zero hid the mismatch, but performance `1` arrived as `0x01000000` rather
than `1`. The service-17 response now emits both raw U32 fields in big-endian
byte order, and the regression test reconstructs the performance field with
`binary.BigEndian` and requires exactly `1`. This correction still requires a
fresh RPCS3 validation. Session updates from `openPrivate=8, filledPrivate=0` to
`openPrivate=7, filledPrivate=1` occurred in the prior run, but both clients
continued candidate evaluation rather than beginning peer DTLS. The exact retail
service-17 reply remains unavailable because the retail LSG capture is encrypted
and its session key is not known.

The same run confirms that both solo clients send operation `5`. Both queries
carry `unranked=1`, while both hosts advertise eight private slots and zero
public slots. Unranked searches therefore use private slots; ranked searches use
public slots. The corrected server repeatedly returns the other client's
candidate.

Further IDA analysis on 2026-08-30 confirms that the service-17 result preserves
the requested entity ID and stores the accompanying U32 at `bdPerformanceValue`
offset `+8`; no authoritative performance value is present in the operation-5
session advertisement. The server now resolves performance values against the
shared matchmaking store: an entity ID that owns an advertised session receives
the deterministic baseline value `1`, while an unknown or stale entity receives
`0`. Regression tests cover both paths. This remains an emulation policy rather
than a retail-derived ranking algorithm and still requires fresh two-client
RPCS3 validation.

The direct peer sequence is also live-confirmed. RPCS3 sends exact 29-byte
`0x0d` traversal requests to the PS3's LAN and advertised external addresses,
receives matching `0x0c` acknowledgements, sends a 17-byte `0x28` QoS request,
and receives the expected 18-byte zero-payload `0x29` reply. The PS3 performs
the reciprocal traversal/QoS sequence. This matches retail's recovered
`0x0d`/`0x0c` and `0x28`/`0x29` order.

The first unresolved transition is now after successful QoS and performance
fetch. No peer-DTLS packet follows. Both clients continue operation-5 searches
and repeat traversal/QoS; each initially reports one filled private slot, and
the PS3 later deletes its session when the run ends. Static analysis has now
located the acceptance/ranking boundary and the downstream secure-association
key assignment. `sub_2FAC00` filters duplicate active
session IDs, initializes the per-search QoS result object, and queues task type
`1`. The type-1 completion path in `sub_2FA008` computes progress as
`100 * completedQoS / candidateCount`, waits for completion or a stall timeout,
then calls `sub_31FDD0`; that check accepts only when
`candidateCount == completedQoS + failedQoS`. It always tears down the QoS
result afterward, and only the accepted branch additionally calls `sub_CFF28`
to advance matchmaking. Therefore the observed operation-5 restart is no longer
an unknown post-performance decision: at least one candidate remains unaccounted
for, or none is promoted into the accepted-candidate count, at the type-1 QoS
completion boundary.

Later TU0 analysis corrected an earlier structure conflation. The 80-byte
party candidate appended by `AddPartyConnectionEndpoint` (`0xCB1F0`) starts
with `+0x44=-1`, `+0x48=-1`, and `+0x4C=INT_MAX`. These are the candidate's QoS
total, probe count, and normalized selection metric. The hash operations at
`0x301E9C` and `0x302368` belong to a different networking structure and do not
explain `sub_CFF28`. `CommitCandidateQoSResult` (`0xCD998`) is the producer for
the candidate fields: it writes `+0x44/+0x48/+0x4C` after `sub_CB538` maps a
completed QoS session/security ID to the 80-byte entry. Therefore `+0x44==-1`
means that this candidate never received a committed QoS result, and the next
diagnostic boundary is `sub_CB538`/`CommitCandidateQoSResult`, not secure-
association lookup or the operation-5 reply codec.

A surgical RPCS3 diagnostic ELF is now available at
`/mnt/d/Reversing/PS3/self resigner/self/default_mp.qos-telemetry.elf`; its
reproducible patcher is `cmd/mw2-qos-patcher`. It replaces only the two direct
calls to `sub_320048` in the type-1 flow, at `0x2FA390` and `0x2FA7A0`, with a
branch to a wrapper in verified zero padding at `0x709280`. The executable LOAD
is extended to include the wrapper without shifting existing file data.

The original version-1 wrapper appended 52-byte big-endian records to
`/dev_hdd0/tmp/mw2_qos.bin`, restored the volatile integer state and special
registers, calls the original `sub_320048`, and returns through the untouched
continuation. Each record is `"QOS1"`, version `0x0001`, tag byte (`1` = abort
call at `0x2FA390`, `2` = accepted-candidate call at `0x2FA7A0`), seven zero
bytes, and the full 36-byte QoS result object. The object contains the accepted
candidate slot at offset `0x00`, `candidateCount` at `0x10`, `completedQoS` at
`0x14`, `failedQoS` at `0x18`, and `acceptedCandidates` at `0x1C`; a nonzero
accepted slot is also the practical `sub_31FDD0` result.

The patcher requires the exact TU0 input SHA-256
`16523486aa1c148eb7e19c40ae98763ec2c85b660dabd46131adb34f815495fb`, validates
both call-site instruction windows and the zero-padding cave, and refuses to
overwrite an existing output. The retail PS3 captures remain the source of
truth.

The 2026-07-31 RPCS3/physical-PS3 retest confirmed the corrected service-17
reply framing. Both clients repeatedly requested one entity ID, the server
logged `entity_count=1`, no fetch-performance popup returned, and matchmaking
still restarted after successful direct peer QoS without beginning peer DTLS.
The subsequent nonempty telemetry captures are
`captures/mw2_qos_rpcs3.bin` (42 records) and `captures/mw2_qos_ps3.bin` (41
records). Every record has tag `2`, so both clients reached the accepted call at
`0x2FA7A0`; neither reached the abort call at `0x2FA390`. The earlier conclusion
that the type-1 boundary rejected or failed to account for a candidate is
therefore disproved. The first 36 object bytes are also not the counters claimed
below: static instructions load `candidateCount` from `+0x5B0`, `completedQoS`
from `+0xE4C`, and `failedQoS` from `+0xE50`. The copied bytes instead contain
the local client's own session ID at object `+0x08` and key at `+0x10` in every
record (`672d64d80a1923fc` / `5c052b8242998ead43affe55ef28f279` on RPCS3;
`60befeffeedb9896` / `aee0dc660b3ae996e5bb19b3ac19bd18` on PS3).

The server-side timeline further localizes the loop after acceptance. Operation
`5` responses were self-inclusive: one solo session produced one result, and two
connected sessions produced two results in session-ID sort order. Both clients
sent operation `2` updates from `openPrivate=8, filledPrivate=0` to
`openPrivate=7, filledPrivate=1`; both sent correctly framed service-17
operation `2` requests for their own account entity ID; then both continued
operation `5` every roughly two seconds. After RPCS3 disconnected, its session
was reclaimed and the PS3's next find reply dropped from two results to its own
single result before it deleted that session. Combined with every accepted-path
telemetry record carrying the local client's own session ID and security key,
this made self-results the strongest testable cause of the post-`sub_CFF28`
loop. Owner exclusion alone still leaves a symmetric two-client result: each
client receives the other and can independently select itself as host after peer
QoS. Operation `5` now records a monotonic creation order and returns only
compatible non-owned sessions created before the requester's own session. The
first creator therefore receives zero candidates and remains host; the later
creator receives the first creator and becomes the joiner. The existing result
object, address/session/key tuple, slot filtering, sorting, and peer QoS path are
unchanged. Connections with no owned session retain the broad directory search
used by non-host callers. Store, handler, and encrypted full-flow regressions
cover the asymmetric policy. A live RPCS3/physical-PS3 retest is still required
to establish whether this reaches peer DTLS and a lobby join.

The first telemetry ELF did reach both hook sites: RPCS3 opened
`/dev_hdd0/tmp/mw2_qos.bin` at the abort hook and later at the accepted hook.
However, the file remained zero bytes because the wrapper loaded stack offset
`0xA8` (the tag byte) as the descriptor for `cellFsWrite` and `cellFsClose`
instead of the descriptor returned by `cellFsOpen` at `0xD4`; RPCS3 logged
`CELL_EBADF` writes. The version-1 patcher correction uses `0xD4` for both calls
and has a regression test that resolves the emitted branch targets and checks
their preceding descriptor loads. That rebuilt diagnostic ELF at the same path
has SHA-256 `f5731e1dcf393186d836da62a5b7d9c49718db049d1573a2048ee16f27b67c6b` and
still changes no matchmaking decision.

The diagnostic patcher has now been extended to version-2 fixed records. It
still hooks the abort and accepted `sub_320048` calls, but it saves the outer
matchmaking object from incoming `r27` before the original call clobbers
nonvolatile state. Version 2 writes to `/dev_hdd0/mw2_qos.bin`: RPCS3 returned
`CELL_ENOENT` for the previous `/dev_hdd0/tmp` path. Each 96-byte big-endian
record contains magic `"QOS1"`,
version `2`, tag, phase, the captured inner-object address, `r27`,
`candidateCount` (`r27+0x5B0`), `completedQoS` (`r27+0xE4C`), `failedQoS`
(`r27+0xE50`), all four selected-candidate addresses from
`r21+0x2110..0x211C`, the QoS address at selected candidate `+0x0C`, the final
QoS/peer address at selected candidate `+0x38`, the QoS port at `+0x3C`, the
inner matched address at `+0x44`, and the first 36 bytes of the inner state.

A third hook at `0x2FA7B8` wraps the accepted path's `sub_CFF28` call. Phase `1`
is emitted immediately before the original call and phase `2` immediately after
it, both with tag `2`; phase `0` remains the accepted `sub_320048` snapshot. This
will show whether `sub_CFF28` returns, how the selected slot/address state
changes across it, and whether the loop occurs after that transition. The
patcher validates the original `sub_CFF28` call target and instruction window,
extends the executable LOAD only into verified zero padding, and preserves the
original call return value and saved state. A verified local build from the
exact TU0 input produced `/tmp/opencode/default_mp.qos-v2.elf` with SHA-256
`038095b972c559f73f112cc01ae7bc8629835f47e9224495e25f0ee3cc0c034f`;
that build is obsolete and must not be resigned. A later RPCS3 run showed its
`cellFsWrite` call as
`sys_fs_write(fd=0, buf=0xD000000001883D78, nbytes=0xD000000001883EA8)` and
then faulted reading that impossible range. The wrapper loaded the correct file
descriptor but reused `r5` for the byte count; the preceding `cellFsOpen` wrapper
preserved `r5`, leaving the count equal to the output-count pointer. The corrected
wrapper now holds the 96-byte record length in nonvolatile `r27`, passes
`r5 = r27`, and restores the caller's original `r27`. Regression tests assert the
complete open/write argument sequence. A verified fresh build from the exact TU0
input produced `/tmp/opencode/default_mp.qos-v2-fixed.elf` with SHA-256
`4a516649d681c3c0af499aaadfb95d353ffc6728f3bb774d0158e8461fb8f7e4`; it must
now be copied to the resigner workspace, resigned, and run in RPCS3.

## Prior playlist dump diagnostic

The diagnostic was reduced to a playlist-only raw dump. The MOTD hook at
`0x0030b598` has been removed and its original `lwz r8, dword_1F91128`
instruction restored. At `0x0030b530`, only the original `bl sub_258BF0` parser
call is replaced with a direct `bl` to the dump wrapper; all surrounding
playlist state writes remain original.

On 2026-07-29 the wrapper was relocated out of the live function at
`0x0034d958` into a newly mapped executable tail at `0x00709160..0x00709280` in
`/mnt/d/Reversing/PS3/self resigner/self/default_mp.elf`. The first executable
LOAD segment's `p_filesz`/`p_memsz` now end at `0x00709280`, before the RW LOAD
at `0x00710000`. The wrapper saves volatile parser arguments plus
LR/TOC/CR/XER/CTR, loads the exact received length from `dword_1F91128`, calls
`cellFsOpen`/`cellFsWrite`/`cellFsClose` at the verified executable stubs, restores
state, and tail-branches to `sub_258BF0`. Its output path is
`/dev_hdd0/tmp/playlists.info`; the immediate pre-relocation backup is
`default_mp.elf.pre_playlist_dump_relocate`.

The retail crash had two concrete causes in the prior IDA patch. The original
call targeted `0x00548a9c`, which is in an ELF segment with read permission but
no execute permission, and its branch targets resolved to non-filesystem stubs.
The later `0x0034d958` workaround called the correct filesystem stubs but
overwrote a real game function, causing a later jump into the dump wrapper with
unrelated register state. The relocated wrapper calls the actual `cellFsOpen`
(`0x00526274`), `cellFsWrite` (`0x00526334`), and `cellFsClose` (`0x005261f4`)
stubs, then tail-branches to the original parser at `0x00258bf0`, preserving the
original LR so parser return resumes at `0x0030b538`.

The relocated branch words and segment bounds were recomputed from their actual
addresses and verified in the patched ELF. The ELF is ready to be resigned and
tested on RPCS3/hardware.

The dump was captured on a retail PS3 connected to the real Demonware service,
and the retrieved raw `playlists.info` is now the emulator fixture. The patched
multiplayer executable was correctly deployed as `default_mp.self`.

Current matchmaking-lobby work:

The 2026-08-02 retail two-PS3 capture
`captures/mw2_ps3_both_matchmaking.pcapng` supersedes the asymmetric directory
policy. Both active lobby TCP streams receive repeated 289-byte encrypted
service replies; this is the exact wire length of a service-5 operation-5 reply
containing two 131-byte session results. The later seeker then sends the retail
peer sequence to the earlier host: type-`0x0d` traversal, followed by a 16-byte
type-`1` bdDTLS Init carrying the selected host's eight-byte session ID. The
retail directory is therefore self-inclusive for both clients. Host selection is
preserved by returning eligible sessions in monotonic creation order, with the
earliest advertisement first, rather than suppressing self and later sessions.
The Go server now uses this self-inclusive creation-order result policy. Comparing
`captures/mw2_rpcs3_ps3_custom_server.pcapng` against retail exposed one remaining
difference: retail held the initial public find until both advertisements existed,
then delivered both 289-byte two-result replies before traversal. The custom server
returned a 161-byte self-only reply to the first client immediately, while the
second client advertised 1.67 seconds later and began peer testing against a
different snapshot. A temporary first-self-only wait was added to reproduce the
retail snapshot, but it blocked the per-connection LSG reader for up to five
seconds. That workaround has now been removed; operation `5` returns the current
snapshot immediately and later client searches observe subsequent advertisements.

The 2026-08-03 no-games retest confirmed the over-filter directly. The physical
PS3 repeatedly advertised/searched game mode `1`, netcode `139`, while RPCS3
advertised/searched game mode `0`, netcode `128`; both were unranked, used map
packs `2`, playlist version `361`, required one slot, and advertised seven or
eight open private slots. All 91 finds returned only the caller's own session, so
the selected slot pool and wait path were not the blocker. The peer failed only
the game-mode and netcode equality checks.

The earlier crash-capture interpretation was incorrect. Direct decryption of the
successful retail two-PS3 capture shows that its peers also differed materially:
the earlier client searched with game mode `0`, netcode `128`, playlist version
`361`, and performance `1000`, while the later client searched with game mode
`1`, netcode `139`, playlist version `426`, and performance `0`. Their operation-1
advertisements echoed the same differences, including advertisement field `8`
matching search `q6` on each host. Both retail clients nevertheless received both
sessions and proceeded to traversal/DTLS, so exact equality filters for game
mode, netcode, playlist version, and performance are disproven. Map-pack flags
were `2` for both clients, so that comparison remains unproven and is not
invented. Operation-5 matching now retains only equal unranked/ranked game type,
the selected slot pool, and required free slots. The regression test uses the
successful retail values and requires both searches to receive both sessions.

The 2026-08-01 live retest confirms the asymmetric result policy reaches the
peer network stage. RPCS3 received the physical PS3's exact common address,
session ID, and security key, then exchanged repeated `0x0d`/`0x0c` traversal
and `0x28`/`0x29` QoS packets with `192.168.0.199:3074`. The RPCS3 probe used
the advertised PS3 session ID's shrunken value, so the candidate identity and
address serialization are working. No peer DTLS packet followed.

The stable-ordering retest confirms that this policy behaves as intended when
the physical PS3 starts first. The PS3 created session `eac3f3f94e2bb9ba`; RPCS3
created second and repeatedly received only that PS3 session. The PS3 received
zero candidates throughout and remained the host. RPCS3 used the returned
identity for traversal and QoS: the `0x28` security value was the first four
bytes of the PS3 session ID, and every observed `0x29` reply matched the current
probe. RPCS3 consumed 29 successful QoS replies, ending with probe 28, but sent
no type-1..6 peer-DTLS packet afterward. At the end of the run the PS3 explicitly
deleted its session and did not recreate it; RPCS3's later zero-result searches
are therefore expected and do not indicate unstable rank reuse.

The supplied telemetry captures are definitively version-1, not malformed
version-2 data. Their size and every `"QOS1"` marker advance by 52 bytes, each
record reports version `1`, tag `0`, and the historical 36-byte candidate
identity object. They therefore cannot answer the outer-state or pre/post-
`sub_CFF28` questions. Static TU0 reconstruction from the verified version-2
artifact confirms the exact input SHA-256 and caller sequence: the accepted path
tears down the inner QoS object, calls `sub_CFF28(r18)`, then immediately resumes
the ordinary matchmaking loop. `sub_CFF28` only clears an 80-byte result entry's
active byte when its field at `+0x44` is `-1`.

The first version-2 live run reached the accepted QoS path, but the diagnostic
itself crashed RPCS3 at `sub_CFF28`. `RPCS3.log` recorded CIA `0x000CFF28`, LR
`0x00709398`, and an unmapped read at `0x3D`; the register dump showed `r3 = 1`.
The wrapper compared only an unmasked 64-bit LR against 16-bit return offsets, so
it misclassified the CFF hook as the abort hook. The abort path then used a
linking call after restoring the caller stack and fell through into the CFF path,
where `ld r3,0x48(r1)` loaded `1` from the wrong frame.

The corrected wrapper masks LR to its low 16 bits before dispatch and tail-
branches, without link, to the ordinary `sub_320048` path. Regression tests now
assert the dispatcher words and require the clear-QoS branch's link bit to be
zero. Rebuilt ELF SHA-256:
`af685196f74a412b0d6dfc15e7c2ff1af0f2a9bea7f112ad5adab13e0dbb2b06`.

The first packaging attempt used `make_fself` and produced a debug FSELF (key
revision `DEBUG`, SHA-256
`9330eb74c18d36a487d6605ced9eaba95e17cb93ccf278d00aa4d3634885e16e`), which
failed immediately when MW2 tried to spawn multiplayer. That artifact is invalid
for this deployment. The ELF was repackaged with `scetool`, using the prior
loadable retail SELF as the template and compressed encrypted sections. A decrypt
round-trip exactly reproduces the fixed ELF. Correct retail SELF SHA-256:
`50f4b6430a2826ab924aff45c90e127915a6f3b06156ed7eba23ac02bb3e3279`.
It is deployed to `dev_hdd0/game/BLUS30377/USRDIR/default_mp.self`; both the old
crashing wrapper and invalid debug-FSELF variants remain backed up, and the old
telemetry output was removed.

The version-2 wrapper path was changed to `/dev_hdd0/tmp/qos.bin` after RPCS3
returned `CELL_FS_EACCES` for `/dev_hdd0/mw2_qos.bin`. The patcher diagnostic
and its path-sensitive regression test now match the embedded path. Rebuilt ELF
SHA-256: `980b1a8ffce02845056fb55929103e07425f20109a90656805a93b1ae74f8188`.
It was repackaged with `scetool` from the same retail template; decrypting the
SELF reproduces the ELF byte-for-byte. New retail SELF SHA-256:
`4300e447fd5f02b65317e8310014ea32279aab6f815e84b601c462265500d6bc`.
It is deployed to `dev_hdd0/game/BLUS30377/USRDIR/default_mp.self`; the previous
retail build is backed up as `default_mp.self.pre-qos-tmp-path`.

The next live run still created no telemetry file. The wrapper's embedded path
had been shortened, but its hard-coded `lis`/`ori` pair still loaded the old
suffix address `0x70963c`; at that address the new string contains only
`"qos.bin"`, so `cellFsOpen` never received `/dev_hdd0/tmp/qos.bin`. The patcher
now derives the path address from the final wrapper layout and patches the load
instructions accordingly, with a regression test tied to the actual embedded
string offset. Tests and `go vet` pass. Corrected ELF SHA-256:
`daa4d4fd9d726863dae81eea88fb6545804b7340ec3e41098eebb58ca68c8cec`.
The repackaged SELF decrypts to that ELF byte-for-byte; SELF SHA-256:
`df31ad6eb741935c534cd319af304d12c42f5a6aafe6c1d52ec76d740debc241`.
It is deployed to `dev_hdd0/game/BLUS30377/USRDIR/default_mp.self`; the prior
broken-path build is backed up as `default_mp.self.pre-qos-pathptr-fix`.

The following live run confirmed all three patched call sites reached the
wrapper and that `cellFsOpen` received the correct path, but RPCS3 reported
`flags=03001` followed by `CELL_ENOENT`. The wrapper had used immediate `0x0601`
as though the SDK constants were hexadecimal; PS3 filesystem flags are octal,
so that value supplied truncate/append without `CELL_FS_O_CREAT`. The patcher
now changes the open flags to `03001` (`0x0c01`: write-only, create, truncate,
append), with a regression assertion on the instruction before `cellFsOpen`.
Tests and `go vet` pass. Corrected ELF SHA-256:
`23aac62fc28151137597e092762d9433e2ff876f0891035a9cfd30abdc9071a8`.
The repackaged SELF decrypts to that ELF byte-for-byte; SELF SHA-256:
`6dde4708b344997d3399872fb28eb85c83b6c85738e3f4492bf5cd2eaba4b04e`.
It is deployed to `dev_hdd0/game/BLUS30377/USRDIR/default_mp.self`; the previous
no-create build is backed up as `default_mp.self.pre-qos-createflag-fix`.

That build crashed RPCS3 inside `sys_fs_open` on the first matchmaking wrapper
call. The live context showed `r4=0x0c01` (`flags=06001`), and RPCS3 explicitly
documents truncate+append as an unsupported combination that may throw. The
wrapper does not require truncation because every record is appended, so the
patcher now uses `CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_APPEND`:
octal `02101`, immediate `0x0441`. Tests and `go vet` pass. Corrected ELF
SHA-256: `177e2a0a629c36dd4ff1bc29c802f1cb750016e15d6729c0ce2d3861451cc817`.
The repackaged SELF decrypts to that ELF byte-for-byte; SELF SHA-256:
`7763a7ef4351852cc074ca788338eedd8c4d4c44056e47c94d9eca9f941c96aa`.
It is deployed to `dev_hdd0/game/BLUS30377/USRDIR/default_mp.self`; the crashing
truncate+append build is backed up as `default_mp.self.pre-qos-trunc-append-fix`.

The corrected version-2 live run produced `/dev_hdd0/tmp/qos.bin`: 6624 bytes,
exactly 69 valid 96-byte big-endian records, comprising 23 repeated phase-0,
phase-1, phase-2 triplets. Every phase-0 record reaches the accepted call at
`0x2FA7A0` with outer pointer `0x01F15174`, `candidateCount=1`,
`completedQoS=1`, `failedQoS=0`, and the saved result-array field still
`0x02731810`. The wrapper's phase-0 `candidate` field equals the outer pointer
because that hook runs before the CFF caller establishes its candidate pointer;
it is not evidence that the two objects alias.

Every phase-1 record at `0x2FA7B8` calls `sub_CFF28` with the valid result-list
object `0x008C1750`, whose entry array is `0x008C38D0`, count is `0x32` (50),
exactly one entry has a nonzero leading byte, all 50 entry pointers are non-null,
and the first entry whose `+0x44` field is `-1` is index 0. Every phase-2 record
returns normally with the same object and array, but the nonzero-leading-byte
count changes from 1 to 0 while the non-null pointer count and first `-1` index
remain unchanged. This exactly matches `sub_CFF28`: it clears byte 0 of entries
whose `+0x44 == -1`; it does not promote a candidate or initiate networking.

This resolves the prior confidence boundary. QoS completion and accepted-path
dispatch are both working, `sub_CFF28` receives the correct object and returns,
and the repeated search cycle is not caused by the earlier invalid `r3` wrapper
bug. The retained candidate identity words vary as monotonic runtime values while
the pointer and counts remain stable; they are diagnostic state, not a missing
session promotion signal. The first unresolved transition is now after accepted
QoS cleanup, in the ordinary matchmaking state-machine consumer that should turn
the retained successful result into join/secure-association work.

1. Trace the owner and consumers of result-list object `dword_74C884` after
   `sub_2FA008` returns, especially reads of the 50-entry array at object `+0x38`,
   entry byte 0, and entry pointer at `+0x48`.
2. Correlate those consumers with RPCS3 network traces and the next task/state
   assignments to identify why no join or peer-DTLS task is queued after the
   accepted callback.
3. Instrument or patch only that exact downstream consumer; do not change QoS,
   service-17 serialization, operation-5 ordering, or `sub_CFF28`, which the
   version-2 telemetry now clears. The 2026-08-03 reciprocal-find retest proves
   the current operation-5 arrays are identical for both requesters and globally
   creation-ordered, with RPCS3 first and the physical PS3 second. Production's
   encrypted 289-byte replies cannot be sequence-decoded from the supplied PCAP
   because its per-session LSG keys are not present in the capture.
4. Once peer DTLS begins, compare the live Init/InitAck/CookieEcho/CookieAck flow
   with the recovered codec and trace the first lobby message.
5. Preserve this run as the baseline: stable asymmetric discovery, operation-2
   slot/attribute updates, and repeated direct `0x0d`/`0x0c` plus `0x28`/`0x29`
   exchanges succeeded, accepted QoS cleanup completed normally, but no peer
   DTLS started.

Static comparison against the labeled COD4 executable maps MW2 TU0's same
post-search pipeline through `sub_2FD758`: accepted candidates pass address
conversion (`sub_D2468`/`sub_D26E0`), join-state gates, and the terminal
`sub_CED10` transition before peer networking. This supports retaining the
current backend response boundary rather than inventing another Demonware task.
A server-side audit did find and correct one independent lifecycle defect in the
compatibility directory. Creation order had been retained per LSG connection,
which made a deleted-and-recreated advertisement keep its former host priority.
Each successful create now receives a fresh monotonically increasing active-session
order. Regression coverage proves that a replacement owner receives older peers
while those peers do not receive the newer replacement. `go test ./...` and
`go vet ./...` pass.

The next diagnostic build is ready. Version-3 telemetry replaces the five
join-pipeline edges in `sub_2FD758` at `0x2FDC00`, `0x2FDC30`, `0x2FDC50`,
`0x2FDC6C`, and `0x2FDC90` with a register-preserving wrapper. It appends one
96-byte tag-3 record to `/dev_hdd0/tmp/qos.bin` before each edge and then
continues to the original `sub_D2468`, `sub_D26E0`, `sub_CED10`, or rejection
path without adding a new link on the original tail branch. Stages 1 through 5
capture the call arguments, produced sockaddr fields, join-ready byte, controller
state, join state, lobby object pointers, and candidate identity words. The
patcher now validates the exact TU0 instruction windows and resolves the original
branch targets independently of the BL link bit; tests and `go vet ./...` pass.
The verified input was `mw2_latest_clean.elf.bak` with SHA-256
`16523486aa1c148eb7e19c40ae98763ec2c85b660dabd46131adb34f815495fb`.
The generated ELF is
`/mnt/d/Reversing/PS3/self resigner/self/default_mp.qos-v3.elf`, SHA-256
`977df858c3b53747ffee327c59966613f2bf40ca68e44ace21ba1df5ac590834`.
Its executable LOAD ends at `0x7094B6`; objdump verification confirms all five
sites branch to wrapper VMA `0x709280`.

The next RPCS3 run did not actually load that v3 image. Its multiplayer executable
segment ended at `0x6ea960`, before wrapper VMA `0x709280`, and
`/dev_hdd0/tmp/qos.bin` was absent after exit. The deployed `default_mp.self` was
SHA-256 `2cd776dcd9ab226392d51357b6d4a1a2ce10df684c33bff04c735a6fba9170cd`,
not the v3 SELF. The valid v3 SELF at
`/mnt/d/Reversing/PS3/self resigner/self/default_mp.qos-v3.self` decrypts
byte-for-byte to the expected v3 ELF; SELF SHA-256
`2522fe7e861f3ef8c2c99d5fd624fbdef0373483c86ddf614450e50c029e0947`.
It is now deployed to `dev_hdd0/game/BLUS30377/USRDIR/default_mp.self`; the
previous image is backed up as `default_mp.self.pre-qos-v3-deploy`, and stale
telemetry was removed.

The 2026-08-02 live run still did not exercise version-3 telemetry because the
installed executable had subsequently reverted to the version-2 image: RPCS3
launched `default_mp.self` with SHA-256
`dcb73b12b5eb0bd175b9d3dbe0c2883ba9385f5ce5bb25d7dec1df475cb8c9e7`, and
no `qos.bin` open appeared in the network trace despite both clients reaching
the matchmaking path. That image is now backed up as
`default_mp.self.pre-qos-v3-redeploy-20260802`. The verified version-3 SELF has
been redeployed, and the installed SHA-256 is again
`2522fe7e861f3ef8c2c99d5fd624fbdef0373483c86ddf614450e50c029e0947`.

The next version-3 RPCS3 run exposed a wrapper-only crash before telemetry could
be consumed. `RPCS3.log` records CIA `0x0070938C`, LR `0x002FA7A4`, an unmapped
read at `0x3D1`, and `r25 == 0`: the accepted-QoS record builder unconditionally
read controller fields at `0x3D1(r25)` and `0x390(r25)`. These two
diagnostic-only fields now emit zero instead of dereferencing the null pointer.
Separately, the stage-1 join edge can enter with saved
`r31 == 0`; that wrapper now checks `r31` before reading `0x10(r31)` or `0(r31)`.
Null candidates leave record fields `0x48` and `0x58` zero, while non-null join
candidates preserve the prior captures. The rebuilt join wrapper is `0x23e`
bytes and ends at VMA `0x70989e`, inside the `0x7098a0` cave limit. Regression
coverage rejects both unsafe controller loads, asserts the complete guarded
join sequence, and validates relocated tail branches. The controller fallback
uses an explicit `li r0,0`, so it cannot serialize a stale register value.
`go test ./...`, `go vet ./...`, and `git diff --check` pass. The guarded ELF was
rebuilt at
`/mnt/d/Reversing/PS3/self resigner/self/default_mp.qos-v3-nullguard.elf`,
SHA-256 `573cf3c5ee9bbcbf92c879b3d8b7527385662fe585cba9b30a7bdf2a95bc9f05`.
It was packaged with `scetool` from the known-good retail v3 template; decrypting
`default_mp.qos-v3-nullguard.self` reproduces the ELF byte-for-byte. SELF
SHA-256: `4bf71aa6bce4054e8b4bba03537a5f7125506c2cb91c839d69953aea9b6eb3d7`.
That SELF is deployed to
`dev_hdd0/game/BLUS30377/USRDIR/default_mp.self`; the previous v3 image is backed
up as `default_mp.self.pre-qos-v3-nullguard-20260802`, and stale `qos.bin` was
removed.

The 2026-08-03 two-client retest completed without a wrapper crash, but the
result is negative for all five version-3 hooks. The deployed SELF still hashes
to the verified null-guard image (`4bf71aa6...`), and RPCS3 appended 408 complete
96-byte records to `/dev_hdd0/tmp/qos.bin` (39,168 bytes). Every record is
version 2/tag 0; there are zero version 3/tag 3 records. Thus accepted QoS and
`sub_CFF28` cleanup continue to run repeatedly, while none of the instrumented
join-pipeline calls at `0x2FDC00`, `0x2FDC30`, `0x2FDC50`, `0x2FDC6C`, or
`0x2FDC90` executes. This is stronger than the prior no-DTLS observation: the
active RPCS3 candidate never reaches the lower half of `sub_2FD758` containing
address conversion and `sub_CED10`.

The next diagnostic target must move earlier in `sub_2FD758`. Instrument its
entry/callers and the gates before `0x2FDC00`, especially the top-level result of
`sub_30CC78` and the state tests that branch around the candidate-processing
half. The current five version-3 hooks should remain as downstream confirmation.

The patcher now implements that version-4 diagnostic. A third wrapper at
`0x7098A0` records 96-byte version-4/tag-4 snapshots for the entry call at
`0xB3F9C`, the fallback/candidate callers at `0x2FDD98` and `0x2FE95C`, the
state-update call at `0x2FD830`, and both gate calls at `0x2FD838`/`0x2FD850`.
Each record captures the hook ID, original LR, input `r3`, the active join-state
pointer and its first three words, plus `dword_74C860[0x1B00/4]`, before tail-
calling the original target. The existing version-2 QoS and version-3 downstream
join hooks remain enabled. Exact TU0 call-site contexts are validated. On
2026-08-29, `files/default_mp_tu0_clean.elf` was verified as the exact IDA TU0
input: MD5 `85908e567a827d383510ee28222b85b6`, SHA-256
`5ecae7aebdffa8b5aa62f087a81f1b9c20f9c4b3dbdc4d41c2c00e65f1072041`, with
sampled code windows at `0xB3F98`, `0x2FD82C`, `0x2FA38C`, and `0x2FDBFC`
matching byte-for-byte. The clean file remains unchanged. The patcher now accepts
only that SHA-256 and generated `files/default_mp_tu0_qos_v4.elf`, SHA-256
`73c26462820244f80829b474c04b5b4391380bb32d536385752f62d7e3283ce8`.
`go test ./cmd/mw2-qos-patcher` and `go vet ./cmd/mw2-qos-patcher` pass.

The 2026-08-29 attempted RPCS3 retest did not execute this telemetry ELF. Its
copy at `/dev_hdd0/game/BLUS30377/USRDIR/default_mp.elf` hashes correctly, but
the launcher requested `/dev_hdd0/game/BLUS30377/USRDIR/default_mp.self`, got
`CELL_ENOENT`, and fell back to `/dev_bdvd/PS3_GAME/USRDIR/default_mp.self`.
RPCS3 consequently loaded the clean executable LOAD size `0x6F9160`, not the
patched `0x6F9A38`; there was no `/dev_hdd0/tmp/qos.bin` open and no telemetry
file. The observed roughly five-second pause was not a wrapper freeze: the
server received RPCS3's first matchmaking operation-5 request at
`19:56:04.812028Z` and deliberately returned it at `19:56:09.813493Z` under the
first-self-only-find delay. That delay has since been removed because it blocks
LSG request processing while waiting for a store mutation.

SELF packaging is now part of every successful `cmd/mw2-qos-patcher` CLI run.
The patcher invokes the repository-local `files/self/tool/scetool.exe` with its
adjacent `data` directory, uses `-0 SELF -1 TRUE -s FALSE` and a known-good
retail SELF template, decrypts the temporary result, requires an exact
byte-for-byte match with the patched ELF, and only then installs
`default_mp.self`. `-scetool-dir`, `-self-template`, and `-self-output` allow
explicit paths; the SELF output otherwise defaults beside the ELF output. A
real WSL/scetool end-to-end run produced the expected ELF SHA-256
`73c26462820244f80829b474c04b5b4391380bb32d536385752f62d7e3283ce8` and
passed the internal decrypt round-trip. The packaged `files/default_mp.self`
has SHA-256 `f89abebbbfd36e5f4552a3fe40a32c072be3146923ce175f5ea03e662c2d23e6`.
The SELF was installed at `/dev_hdd0/game/BLUS30377/USRDIR/default_mp.self` and
successfully executed under RPCS3 on 2026-08-29. RPCS3 created
`/dev_hdd0/tmp/qos.bin` with 7,488 bytes: 78 complete 96-byte records. All are
version-2/tag-2 QoS records, consisting of 26 identical phase cycles at hook
addresses `0x30A7A0` (phase 0) and `0x30A7B8` (phases 1 and 2). No version-3
join-pipeline or version-4 early-gate record was emitted. This proves the
packaged telemetry SELF works and the QoS acceptance/CFF path repeatedly runs,
but none of the instrumented `sub_2FD758` entry/caller/gate sites executes in
this test. The next diagnostic must trace the path leaving `0x2FA7B8` and locate
the actual caller/state transition used after successful QoS processing rather
than moving further inside the currently unvisited `sub_2FD758` path.

The newly added World at War PS3 Demonware documentation has now been
cross-referenced against this remaining issue in
`docs/two-player-lobby-investigation.md`. Its recovered flow independently
supports the current boundary: service-5 find results are candidate offers,
followed by client-side QoS, host selection, party/session-state copying,
socket-router registration, and peer DTLS rather than another central join RPC.
It also shows the same `SecurityID8 + CommonAddr25 + SecurityKey16` join material
in both matchmaking and native-invite paths.

A follow-up TU0 static pass has now mapped that model directly onto MW2 without
a new telemetry run. `sub_2FDE58` copies an exact 49-byte native join block into
`dword_74C860+0x160`, and `sub_2FDCD8` copies the same 49 bytes into the active
party/session object at `dword_74CB70+8` after `sub_323448` supplies the local
64-bit identity. In the public-matchmaking path, `sub_2FE2C0` calls
`sub_2FD758` only after join state `dword_74C870+0x390` equals 2 and a four-entry,
0x48-byte local-controller scan finds state 2 with identity equal to
`qword_1F37488`. `sub_2FD758` then gates peer setup on the local NP classifier
`sub_30CC78` (classifier state 2, produced only by NP state field 9), local global
state 4 or 6 through `sub_30CC40`, a live object at `dword_74C860+0x2124`, and
per-controller state 2 through `sub_2F8E68`. Only after those local predicates
does it reach address conversion and `sub_CED10`.

None of those early predicates reads operation-5 attributes, slots, performance
values, or another server response. The server already emits TU0's recovered
wire order (`CommonAddr25`, `SecurityID8`, `SecurityKey16`); TU0 performs the
conversion into the invite/party 49-byte order itself. Therefore no confident
backend matchmaking, QoS, service-17, result-order, or added-join-RPC fix is
currently justified. Static producer analysis has now separated the local controller transition from
the NP classifier. `sub_2F9598` is the sole writer of each 72-byte controller
record's state at `+0x28`; its only callers are `sub_2F9898`, which passes state
`1`, and `sub_2FC888`, which passes state `2`. The state-2 path is therefore a
normal local controller/party teardown-or-finalization transition, not data
decoded from matchmaking. For controller zero, `sub_2F9598` copies the local NP
identity through `sub_323448`/`sub_323390` only when `sub_30CC78` is true.
`sub_30CC78` is exactly the predicate `sub_318188() == 2`; this requires the NP
state object at `dword_74D464` to be idle with `dword_2023904 == 9`.
`sub_3184E8` clears that field and promotes it to 9 only when the retained NP
async object reports terminal status 2, while `sub_3182C8` produces retry state
1 after timeout/backoff. Separately, `sub_2F94C0` is an explicit reset producer
for join state `dword_74C870+0x390`, writing zero and clearing the adjacent
49-byte block. A corrected xref pass found the previously missed value-2
producer: `sub_2F8DF0` writes `2`, and `sub_2F8E10` is a thunk to it.
`sub_2FD758` calls that thunk unconditionally at `0x2FD7C0` before testing the
NP classifier. Thus the entry hook at `0xB3F9C` and the alternate tail-call at
`0x2FDD98` can establish join state 2 directly; only the normal pump caller at
`0x2FE95C` requires state 2 beforehand through `sub_2F8E18` plus the local
controller-record scan. This removes the alleged hidden server-driven producer
and further confirms the unresolved predicates are local NP/controller/party
lifecycle state, not operation-5 or service-17 reply fields.

No backend protocol defect is evident from the latest two-client server log.
Both clients created one valid session, repeatedly received operation-5 find
replies from the shared store, and accepted QoS packets; no lower join-pipeline
hook then fired. The earliest likely blocker remains the local NP predicate
`sub_30CC78` immediately after the now-confirmed state-2 write, or a later local
controller/object predicate inside `sub_2FD758`. The 2026-08-29 version-4 telemetry run completed without a crash and wrote
`/dev_hdd0/tmp/qos.bin` correctly, but a byte-level review on 2026-08-29 found
that the 7,488-byte file contains 78 version-2 records and zero version-4
records. The original gate wrapper serialized its snapshot into an executable-
segment scratch area and never called `cellFsOpen`/`cellFsWrite`/`cellFsClose`;
therefore the absence of version-4 records does not prove that the gate sites
were unvisited. The patcher now uses six full 16-byte gate stubs, preserves each
original callee and hook ID, calls the original target first, captures its
return value and condition register, and appends a 96-byte version-4 record to
`/dev_hdd0/tmp/qos.bin`. Regression tests verify the six entry targets, file-I/O
branches, path, record address, size, and return-state restoration. The repaired
artifact is `files/default_mp_tu0_qos_v4_file.self`, SHA-256
`ca7a3def7ec81e1c8a4dccf03b05eca71834bf29cd7187948120639dcf389064`; its ELF
is `files/default_mp_tu0_qos_v4_file.elf`, SHA-256
`bd1c245dd6a5e047bc4a13d2a13b0ab214a0050097347b4c5d606be65e2e4f70`.
The next required test is to install that SELF, delete stale `qos.bin`, repeat
the same two-client scenario, and return the new file. Matchmaking replies
should remain unchanged.

A separate 2026-08-30 two-client failure was traced to LSG connection handling,
not shared matchmaking ownership. RPCS3 (`192.168.0.117`) and the physical PS3
(`192.168.0.199`) had distinct LSG connection IDs and independently owned
sessions; closing the PS3 reclaimed only its own session, while RPCS3 continued
to receive valid service-4 replies. At `01:37:00.300548470Z`, RPCS3 sent a
four-byte `00 00 00 00` LSG record after 90 seconds of inactivity. The server
rejected body size zero and closed the otherwise healthy connection, after which
the client reconnect loop produced invalid-HMAC step-2 requests and displayed
"Communication with the Activision servers has been interrupted." The same
zero-length LSG packet appears in the earlier
`captures/mw2_rpcs3_ps3_no_games_found.pcapng` at frame 164, confirming it is a
client keepalive. `readLSGFrame` now accepts the four-byte keepalive, and the LSG
loop logs and consumes it without decrypting, incrementing frame state, replying,
or closing the connection. Parser and live-loop regression coverage was added;
`go test ./...` passes. The next live test is to leave one client idle for more
than 90 seconds, quit the other client, then start matchmaking on the idle client
and confirm the original LSG connection remains active. This transport fix is
independent of the unresolved post-QoS join-pipeline gate.

IDA comments/bookmarks now also mark `0x2F8DF0`, `0x2F8E10`, `0xB3F9C`,
`0x2FDD98`, and `0x2FE95C`, alongside `0x2FDE58`, `0x2FE700`, `0x2FD7C0`,
`0x2FD850`, `0x2FDC00`, `0x2FDC6C`, `0x2F9598`, `0x2F9908`, `0x2FC8F4`,
`0x2F94C0`, `0x3182C8`, `0x3184E8`, and `0x30CC78`.

### In-Memory Promotion Snapshot Retest (2026-08-30)

The focused decision hook at `0x2FA760` was rebuilt as a leaf-only in-memory
snapshot wrapper. It now makes no `cellFsOpen`, `cellFsWrite`, or `cellFsClose`
calls and does not move the live stack pointer while external code runs. On its
first invocation it writes the same version-5, tag-5, stage-1 96-byte record to
reserved zero-filled memory at `0x75E348`; the one-shot guard remains at
`0x75E340`. The overwritten `cmpwi cr7,r0,0` is replayed immediately before
return.

The hook is enabled again in generated images. The stable abort/accept/CFF
filesystem logger remains enabled independently, so a retest can first answer
whether the previous RPCS3 crash was caused specifically by filesystem HLE from
inside the decision hook. The in-memory record is not yet flushed to `qos.bin`;
that is intentionally deferred until the leaf snapshot proves crash-free.

Regression coverage rejects filesystem calls or the telemetry path in the
decision wrapper, requires the one-shot guard and snapshot buffer selection,
and verifies the promotion-state loads plus final comparison/return sequence.
`go test ./cmd/mw2-qos-patcher`, `go vet ./cmd/mw2-qos-patcher`, and
`git diff --check` pass.

Retest artifacts:

- patched ELF: `files/default_mp_tu0_qos_v10.elf`
- patched ELF SHA-256: `013d829f9aab2bb91127eda7b347b6744f70648d7152ee4c13bb731e4e8f72f0`
- packaged SELF: `files/default_mp_qos_v10.self`
- packaged SELF SHA-256: `057695bae8bc27d839d3c78d4fc9642f7fd69c1741d39e5833066b7966896e6e`
- installed deployable: `files/default_mp.self`

The v10 live retest completed on 2026-08-30. The final public search involved
RPCS3 at `192.168.0.117` and the physical client at `192.168.0.200`; a third
client had also connected during the server lifetime but was not active in the
final two-session search. RPCS3 passed the former `0x2FA764` crash point and ran
for about 2 minutes 20 seconds without an access violation, verification
failure, or fatal emulator error. The game eventually became unresponsive while
matchmaking remained active, but the trace shows a later peer-network retry
loop rather than a decision-wrapper crash. The leaf-only in-memory promotion
snapshot is therefore stable and the previous crash was caused by filesystem
HLE calls from inside that hook.

`/dev_hdd0/tmp/qos.bin` contains 1,728 bytes, exactly 18 complete 96-byte
records, SHA-256
`72161669127ee3fdf1e0fd81b4b4dbd3df3a048e445776baaef5b2b32fa4ca1b`.
All records are the unchanged version-2/tag-0 filesystem telemetry: six
abort/accept/CFF cycles at `0x30A7A0` and `0x30A7B8`. No version-5 record is
expected there because the decision snapshot remains memory-only at `0x75E348`.

Both clients received the same self-inclusive, creation-ordered two-result
operation-5 reply. Direct traversal completed in both directions. The physical
client's type-`0x28` QoS request reached RPCS3 and RPCS3 returned type `0x29`,
but RPCS3 then sent four type-`0x28` probes to the physical client without any
`0x29` response. No type-1 through type-6 peer-DTLS packet followed. RPCS3
updated its own advertisement from private slots `8/0` to `7/1`, requested one
service-17 performance value, continued operation-5 searches, and returned to
repeated type-`0x0d` traversal after the QoS timeout. The physical client made
no corresponding slot update and its LSG connection later closed, reclaiming
its session. RPCS3's next find then contained only its own advertisement and it
deleted that session shortly afterward.

This run does not justify changing the retail-proven self-inclusive directory,
creation ordering, QoS serialization, or performance reply. It establishes that
the immediate live blocker is asymmetric peer QoS responsiveness before local
promotion and peer DTLS. The next test should instrument or debug the physical
client's type-`0x28` receive/reply path and capture the in-memory `0x75E348`
snapshot through an RPCS3 debugger/watchpoint rather than adding another
in-process filesystem flush.

A follow-up comparison against both successful two-client captures and the ELF
narrows that target further. The physical PS3 is demonstrably capable of replying
to RPCS3's identical 17-byte MW2 QoS requests in the successful captures, so the
wire format, RPCS3 socket, and basic PS3 receive path are not the differentiator.
The failed v10 trace sent exactly four complete requests to
`192.168.0.200:3074`; the first was
`28 46 1c d5 00 00 00 00 00 00 00 00 00 b1 1c 35 8b`, followed at the normal
approximately 0.9-second retry interval by new request IDs with the same short
security ID `b1 1c 35 8b`. No type-`0x29` packet returned. ELF analysis confirms
QoS listening is explicitly enabled for a local session by `sub_3066F0`, which
registers the session's security ID/key and sets the session byte at `+0x22c` to
one; `sub_306660` unregisters it and clears that byte. Therefore the leading
hypotheses are now a physical-client listener lifecycle/state transition or a
mismatch between its locally registered security ID/key and the advertisement
returned by operation 5, not packet serialization. The next capture should log
or inspect the physical client's advertised eight-byte security ID/key, verify
that `shrinkSecId` equals `b1 1c 35 8b`, and breakpoint the `sub_3066F0`/
`sub_306660` paths to determine whether the listener was never registered or was
removed before RPCS3's first probe.

The server now records the exact generated eight-byte session/security ID and its
`shrinkSecId` little-endian `u32` for service-5 operation-1 replies and every
operation-5 result. Full 16-byte matchmaking security keys are emitted only by
the existing explicit sensitive logging mode. This makes the next two-client run
able to compare the physical client's advertisement, returned find result, and
observed type-`0x28` probe identity directly.

### Focused Promotion-Decision Telemetry (2026-08-29)

Implemented the next diagnostic in `cmd/mw2-qos-patcher` and produced
`files/default_mp.self`. The clean retail packaging template is preserved as
`files/default_mp_tu0_clean.self`. Deployable SELF build artifacts belong under
`files/`; `captures/` is reserved for packet captures, logs, telemetry, and
other debugging or reverse-engineering inputs.

The new hook replaces `cmpwi cr7,r0,0` at `0x2FA760`, immediately before the
branch that decides whether to invoke `sub_2F7660`. The wrapper records a
version-5, tag-5, stage-1 96-byte snapshot and then re-executes the overwritten
comparison so control flow is unchanged.

Captured fields:

- `0x0C`: LR / return site
- `0x10..0x2C`: live `r18`, `r19`, `r20`, `r21`, `r22`, `r24`, `r27`, `r31`
- `0x30`: live `r0`, the exact value tested by `cmpwi cr7,r0,0`
- `0x34`: `*(u32 *)(r27 + 0x5B0)`
- `0x38`: `*(u32 *)(r27 + 0xE4C)`
- `0x3C`: `*(u32 *)(r27 + 0xE50)`
- `0x40`: `*(u32 *)(r27 + 0xE1C)`
- `0x44`: `*(u32 *)(r27 + 0xE20)`
- `0x48`: `*(u32 *)(r21 + 0x2100)`
- `0x4C`: reserved and written as zero

The first RPCS3 test crashed at wrapper address `0x709740`. The log showed that
`*(u32 *)(r21 + 0x2100)` was `0x38A2`, so the attempted nested byte load from
`0x38AE` raised an invalid-instruction memory fault. The wrapper now records the
raw `r21 + 0x2100` value at `0x48` without dereferencing it; a regression test
rejects the unsafe `lbz r0,0x0C(r0)` instruction.

The next RPCS3 test crashed at original address `0x2FA764`, where the branch read
CR7 after the wrapper returned. The wrapper had replaced both `lbz r0,0x0C(r9)`
and `cmpwi cr7,r0,0`, but replayed only the comparison. Its telemetry path load
left `r0=0x60000000`, so the branch incorrectly fell through and later code used
that value as a pointer. The wrapper now replays `lbz r0,0x0C(r9)` immediately
before `cmpwi cr7,r0,0`; regression coverage requires both instructions.

The following RPCS3-only retest still crashed at `0x2FA764`. Its context showed
`r31=0x60000000`, while the immediately preceding HLE `cellFsOpen`,
`cellFsWrite`, and `cellFsClose` calls failed because `qos.bin` did not exist.
The retail PS3 did not crash during the same search. RPCS3's direct filesystem
HLE path therefore clobbered nonvolatile PPU registers across the telemetry
calls. The decision wrapper now saves and restores `r14` through `r31` around
all three calls and uses a `0x220`-byte stack frame; regression coverage checks
the `r14`/`r31` save and restore instructions.

The existing version-3 abort/accept/CFF records remain enabled. Earlier
version-4 join and gate hooks were removed from the generated image to keep this
test focused and reduce instrumentation risk.

Build artifacts:

- clean input: `files/default_mp_tu0_clean.elf`
- clean input SHA-256: `5ecae7aebdffa8b5aa62f087a81f1b9c20f9c4b3dbdc4d41c2c00e65f1072041`
- patched ELF SHA-256: `d3c4c3c4e28d41a7b44a966e0ea9f26c3cf7ba7db557e42e40d0ab79fba1849f`
- `files/default_mp.self` SHA-256: `3a45a5986f79280b6e1740516d47239ee4502d6676a51c3b07a9cc663311d331`

Next RPCS3 test:

1. Deploy `files/default_mp.self` as the multiplayer executable.
2. Delete `/dev_hdd0/tmp/qos.bin` before launch.
3. Reproduce one failed public-match search.
4. Preserve `qos.bin`, `RPCS3.log`, and `server_log.log`.
5. Inspect the version-5 snapshot first. If `r0` is zero, the promotion call is
   skipped at this exact gate; compare the captured search/controller fields
   against a successful or later-stage path before instrumenting deeper.

## Current implementation areas

- `internal/auth/raw_server.go`: retail auth/LSG connection handling, logging,
  and encrypted response dispatch.
- `internal/auth/legacy_response.go`: dynamic MW2 authentication response and
  ticket generation.
- `internal/auth/lsg_record.go`: LSG framing, encryption/decryption, IV
  derivation, and request HMAC validation.
- `internal/auth/lsg_protocol.go`: retail service dispatch and minimal title,
  DML, bandwidth, and stats handling.
- `internal/auth/lsg_storage.go`: bit-packed storage parser, corrected
  operation-5/7/8 replies, `bdFileInfo`, and playlist loading.
- `internal/auth/lsg_storage_test.go`: storage request/reply and blob-layout
  regression tests.
- `internal/auth/lsg_matchmaking.go`: exact service-5 decoders and
  create/update/delete/zero-or-nonempty-find handlers.
- `internal/auth/lsg_matchmaking_store.go`: process-wide, mutex-protected
  retail session directory with generated ID/key material.
- `internal/auth/lsg_matchmaking_test.go`: golden request/reply, malformed
  query, nonempty result, and direct shared-directory lifecycle tests.
- `internal/auth/full_flow_test.go`: encrypted two-client storage op-8/op-5
  through create/find/update/delete and candidate-tuple preservation.
- `internal/auth/retail_auth_full_flow_test.go`: two real TCP authentication
  exchanges through issued one-use LSG tickets, storage, and matchmaking.
- `internal/auth/lsg_matchmaking_store_test.go`: deep-copy, ordering, capping,
  and concurrent-access tests.
- `internal/services/nat/server.go`: strict MW2 v2 UDP public-address and NAT
  request validation, exact serializers, primary/alternate reply routing, and
  the exact current-legacy introducer relay.
- `internal/services/nat/server_test.go`: PCAP-derived golden bytes, IPv4/port
  endianness, malformed rejection, and localhost source-socket integration.
- `internal/peerproto`: strict, non-network-wired CommonAddr, QoS,
  NAT-traversal, and complete peer-DTLS packet/replay codecs with independent
  golden vectors.
- `docs/demonware-matchmaking.md`: complete recovered service-5 schemas and
  confidence boundary.
- `docs/demonware-ip-discovery.md`: exact `0x1e`/`0x1f` and `0x14`/`0x15`
  wire formats plus the traversal/QoS scope boundary.
- `docs/demonware-peer-qos.md`: exact post-find peer packet layouts, HMAC,
  receive behavior, retry state, and the central-introducer boundary.
- `docs/demonware-peer-dtls.md`: exact peer secure-association packet layouts,
  security-material roles, state machine, retries, and central-service boundary.

### Promotion-Telemetry Stack Anchor (2026-08-29)

IDA confirmed `0x526274`, `0x526334`, and `0x5261F4` are valid direct import
thunks for `cellFsOpen`, `cellFsWrite`, and `cellFsClose`. Each thunk stores its
imported TOC at `0x28(r1)` before tail-calling the HLE implementation. Live v5
telemetry nevertheless showed the wrapper returning with `r1` exactly `0x80`
below its expected value, causing nonvolatile restores to read the wrong frame
and return `r31=0x60000000` instead of the captured pre-hook value `1`.

The decision wrapper now saves its frame pointer in nonvolatile `r14` before the
filesystem calls and restores `r1` from `r14` immediately after every import
thunk returns. `r14..r31` remain saved and restored around the wrapper, so this
does not alter caller-visible nonvolatile state. Regression coverage verifies
that every filesystem call is followed by the stack-pointer restoration.
`go test ./cmd/mw2-qos-patcher` and `go vet ./cmd/mw2-qos-patcher` pass.

Generated test artifacts:

- `files/default_mp_tu0_qos_v6.elf` — SHA-256
  `4254fc7c4e06470afc09ccbe9213c3e3120f892c8ae72036848d372571d1a660`
- `files/default_mp_qos_v6.self` — SHA-256
  `62da03834f8f8e815376b649ac695effd8462bacd2e7c297a4d0c0fb6f24dd9d`

The v6 SELF was tested on both RPCS3 and retail PS3 and still crashes. RPCS3
reproduced the same failure immediately after the 96-byte decision record closed:
`r1=0xd000f210` instead of the pre-hook `0xd000f290`, `r31=0x60000000`, and the
fatal read remains at `0x002fa764`. This proves the import-thunk return path also
corrupts the nonvolatile `r14` stack anchor; restoring `r1` from a GPR is not
sufficient. The v7 patch keeps the `r14` restore after open/write but, for the final close,
directly reverses the observed `-0x80` displacement with `addi r1,r1,0x80`
before restoring the saved register image. Regression coverage verifies this
split recovery sequence. `go test ./cmd/mw2-qos-patcher`,
`go vet ./cmd/mw2-qos-patcher`, and `git diff --check` pass.

Generated test artifacts:

- `files/default_mp_tu0_qos_v7.elf` — SHA-256
  `bc7ce8e51263f0665c4d54801129a1e61e6fd85a0f7597bdc2f095be325f53e2`
- `files/default_mp_qos_v7.self` — SHA-256
  `aee85887438927ddec7b1550889c477580709a4f7d85388b21387476a469fc76`

The v7 RPCS3 test still crashed, but the stack fix worked: execution reached the
wrapper epilogue at `0x00709894` with `r1=0xd000f310`, and a complete 96-byte
record was written. The fault changed to a read at `0x6c` because the wrapper
restored volatile `r9=0x60` and then incorrectly replayed `lbz r0,0xc(r9)`.
That load had already executed at `0x002fa75c`; the hook replaces only the
following `cmpwi` at `0x002fa760`.

The v8 wrapper therefore restores the original `r0` and executes only the
replaced `cmpwi cr7,r0,0` before returning. Regression coverage rejects either
form of repeated `lbz`. `go test ./cmd/mw2-qos-patcher` and
`go vet ./cmd/mw2-qos-patcher` pass.

Generated test artifacts:

- `files/default_mp_tu0_qos_v8.elf` — SHA-256
  `e005ed0057f32fd27ce8026b29a6099308c0bc34bbb803dbac9803cb9288bd73`
- `files/default_mp_qos_v8.self` — SHA-256
  `f0b9534ab3bc41812f842eb88d6f2b2e21571071a91eda8694eb316fff8741e2`

The v8 RPCS3 run produced one complete 96-byte decision record, resumed the
matchmaking loop, and reached the same hook again about eight seconds later. The
second invocation crashed during `cellFsOpen` before another record was appended.
The diagnostic has therefore been made one-shot: unused writable tail space at
`0x0075e340` holds a zero-initialized guard; the first hook sets it before opening
the file, while later hooks skip directly to register restoration and the original
`cmpwi cr7,r0,0`. Regression coverage verifies the guard load/store and its branch
target. `go test ./cmd/mw2-qos-patcher`, `go vet ./cmd/mw2-qos-patcher`, and
`git diff --check` pass.

Generated and installed test artifacts:

- `files/default_mp_tu0_qos_v9.elf` — SHA-256
  `fa0324a482ac08a7a66a2b8f61cb3b692b22548f90708ff672fdc46e22d6888f`
- `files/default_mp_qos_v9.self` — SHA-256
  `58e3594e6ce04d509a67630d82a65640113e1822696b32089fd0f5f102919c1c`

The v9 RPCS3 run again terminated during the first `cellFsOpen`. The log ends
after `sys_fs_open()` successfully returns fd 12; there is no emulated PPU fault,
write, or close entry. Nevertheless, the host file contains the complete 96-byte
record, so the captured gate state is valid: live `r0` at `0x002fa760` was `1`.
The original `cmpwi cr7,r0,0` therefore permits the call to `sub_2F7660`; the
promotion veto is not the reason the accepted candidate returns to searching.
The other captured values were `r18=0x008c1750`, `r19=0x01f15fd0`,
`r20=0x01f15174`, `r21=0x01f14ed8`, `r22=1`, `r24=0x01f16044`,
`r27=0x01f15174`, and `r31=1`; the six inspected controller/search fields were
`0, 1, 1, 0, 0, 0`, and `*(u32 *)(r21+0x2100)=0x01c8b538`.

Because RPCS3 can terminate inside the filesystem HLE import before wrapper code
can regain control, no further live build should use this in-process file probe.
`files/default_mp.self` has been restored to the clean retail TU0 SELF, SHA-256
`f89abebbbfd36e5f4552a3fe40a32c072be3146923ce175f5ea03e662c2d23e6`.
The next investigation should move past the now-confirmed promotion call and use
non-filesystem observation (RPCS3 debugger/watchpoints or server/network-visible
behavior) around `sub_2F7660` and its downstream lobby handoff.

### Matchmaking Identity and Bidirectional QoS Retest (2026-08-30)

The new two-client run conclusively removes the advertised session identity,
`shrinkSecId`, listener registration, and asymmetric QoS response hypotheses.
The physical client at `192.168.0.199` created session ID
`f1a6340259199a59` with short ID `0x0234a6f1`; RPCS3 at `192.168.0.117`
created `d4bed225c00a9e3c` with short ID `0x25d2bed4`. Every operation-5 reply
returned those exact IDs and the corresponding 16-byte keys remained stable.

RPCS3's network trace then shows both directions using the correct advertised
identity. Its outgoing type-`0x28` probes to the physical client end in
`f1 a6 34 02`, while incoming physical-client probes end in `d4 be d2 25`.
Both clients answered every observed probe with an 18-byte type-`0x29` reply,
`enabled=1`, zero data bytes, and the matching probe ID. The trace contains
probe sequences `0` through `14` in both directions, so this was sustained
bidirectional QoS rather than a single successful exchange.

Both clients subsequently issued service-17 operation-2 performance requests,
but continued issuing operation-5 searches instead of beginning peer DTLS or a
lobby handoff. Near the end, the physical client sent matchmaking operation `3`
and its advertisement disappeared; RPCS3's next search contained only its own
session, then its LSG connection closed and that final session was reclaimed.

A fresh static pass confirms that `sub_2F7660` is not the candidate-commit or
lobby-handoff function. It is a small selector that maps a match-type index plus
one of five criteria to one of four offsets in the matchmaking dvar block. Its
callers at `0x2F78A8` through `0x2F7A78` are dvar get/set wrappers, not the
post-QoS state transition. The earlier filesystem probe proved only that an
accepted candidate path invokes one of these accessors; it did not prove that a
promotion or join routine ran. The next reverse-engineering target must therefore
move back to the accepted branch in `sub_2FA008`/`sub_2FE2C0`, identify the actual
candidate state write and the consumer that should reach the existing search-
session/lobby join path, and avoid treating `sub_2F7660` as the handoff boundary.

Static tracing now eliminates another misleading state path. `sub_2FE2C0` reads
the controller record at `dword_74C860 + 0x28` through `sub_2F8CD8(0)` and
compares it with `sub_2F93B0(0)`. That desired value is entirely local: controller
0 returns state `2` only when `sub_30CCB8` and `sub_30CC78` report NP readiness,
otherwise state `1`; nonzero controllers return `0`. The matching producers are
in `sub_2FD5A8`: state `1` dispatches to `sub_2F9898`, state `2` dispatches to
`sub_2FC888`, and both ultimately call `sub_2F9598`, which writes the 72-byte
controller record's `+0x28` field. The accepted-QoS path at `0x002fa7b8` instead
calls `sub_CFF28`, which only clears 80-byte candidate entries whose signed
`+0x44` status is `-1`; it does not write this controller state. Therefore the
controller `+0x28` synchronization and its `sub_2FD758` gate are not the missing
candidate-to-join handoff.

The accepted branch in `sub_2FA008` has now been separated from the later
selection state as well. Matchmaking task type `1` owns the QoS evaluation:
`MatchmakingQoSEvaluationStatus` returns `0` while pending, `1` on completion,
and `2` on failure/inconsistency. Before acceptance, the pump maps each completed
QoS result through `sub_CB538` and calls `CommitCandidateQoSResult` to populate
the matching candidate's `+0x44/+0x48/+0x4C` metrics. It then logs the completed
count, clears the QoS object and task slot, and calls
`InvalidateCandidatesWithoutQoS` only to remove candidates that remain
unresolved. It does not directly invoke the later selector or join routine. The
asynchronous backend task state is created and advanced elsewhere, while
`sub_2F9DB8`/`sub_320C20` only poll its completion; that task-state transition is
not itself accepted-candidate promotion.

Further IDA typing corrects the interpretation of case `4`: it is not a
post-candidate selection/aggregation stage and is not reached by advancing a
type-1 task. It owns the independent global `QoSProbeEvaluation` object at
matchmaking context `+0x198`. `StartQoSProbeEvaluationIfIdle` starts that object,
performs its initial update, and creates a task whose type is `4`. The case-4
pump waits for evaluator state `7`; success copies the primary and secondary
48-byte probe-stat blocks into the context, stores their scaled metrics at
`+0x150` and `+0x154`, sets byte `+0x2108` to `1`, and clears dword `+0x210C`.
Failure clears `+0x2108` and arms `+0x210C` with the retry deadline. The evaluator
layout is now typed in the IDB (`active +0x0C`, `state +0x10`, `error +0x14`,
probe stats `+0x48` and `+0x78`), and the task pump, start/retry helpers, and
state-machine routines are named and annotated. Therefore these fields describe
the client's own network-probe readiness, not accepted-candidate promotion. The
external owner/consumer is now identified below as the party candidate array and
`SelectJoinablePartyCandidate`; the remaining failure occurs before that selector
because the sole entry is never populated by `CommitCandidateQoSResult`.

## Accepted-QoS candidate owner and selector comparison

Static reconstruction now closes the ownership gap left by the version-2 QoS
capture. `AddPartyConnectionEndpoint` (`0x000cb1f0`) appends each 80-byte
candidate to the party/session object's array at object `+0x38`, stores the
candidate count at `+0x3C`, and initializes `+0x44=-1`, `+0x48=-1`, and
`+0x4C=INT_MAX`. These fields are QoS-selection state, not a CommonAddr hash.
During type-1 task pumping, `sub_CB538` (`0x000cb538`) maps each completed QoS
result's 8-byte session/security ID back to this candidate array. The call at
`0x002fa300` then enters `CommitCandidateQoSResult` (`0x000cd998`), which accepts
only an active unresolved entry and writes total latency/value to `+0x44`, probe
count to `+0x48`, and a normalized metric to `+0x4C`. The accepted branch later
calls `InvalidateCandidatesWithoutQoS` (`0x000cff28`), which only clears the
active byte of entries that still have `+0x44==-1`.

Candidate selection belongs to a separate party-state owner. The large party
pump `sub_D5C40` (`0x000d5c40`) calls `SelectJoinablePartyCandidate`
(`0x000d5750`). That selector rejects unresolved candidates, compares their
normalized `+0x4C` values, and retains the lowest-metric survivor. It then calls
`ProbeSelectedPartyCandidate` (`0x000d2468`); on success,
`CopySelectedCandidateToPartyJoinState` (`0x000d26e0`) copies the selected
candidate's 49-byte endpoint tuple and metrics into the party join-state fields,
followed by `sub_CED10`. On probe failure it invalidates the candidate and
continues selection. `sub_2FE2C0` reaches this party pump independently through
`sub_CF038`, so the type-1 task callback is not expected to call the selector
directly.

This is the MW2 equivalent of the recovered World at War sequence:

- candidate insertion: WaW `0x001e30f8` -> MW2 `AddPartyConnectionEndpoint`;
- QoS callbacks/filtering: WaW `0x00477e98`/`0x00477dd8` and `0x001e5b30` ->
  MW2 `sub_CB538`, `CommitCandidateQoSResult`, and
  `InvalidateCandidatesWithoutQoS`;
- best-host selection: WaW `0x001e92d8` -> MW2
  `SelectJoinablePartyCandidate`;
- party/session copy: WaW `0x00448588` -> MW2
  `CopySelectedCandidateToPartyJoinState`;
- network start: WaW `0x001f0b50` -> MW2's `sub_CED10` path.

The live version-2 result is therefore narrower than previously stated. The
candidate count and completed-QoS count both reach one, but the candidate still
has `+0x44==-1`, so `sub_CB538` either fails to map the completed QoS identity or
`CommitCandidateQoSResult` rejects/skips the mapped entry. Cleanup correctly
removes that unresolved candidate; the selector consequently has nothing to
promote. The next diagnostic should hook around `0x002fa2c0..0x002fa304` and
record the completed QoS session/security ID, `sub_CB538` return index, candidate
active byte, candidate `+0x44/+0x48/+0x4C`, and the return value from
`CommitCandidateQoSResult`. This should distinguish an identity mismatch from a
candidate-state rejection without another broad matchmaking dump.

Verified IDA names and comments were applied for the functions above, and
`captures/ida/default_mp_tu0.i64` was saved in place.

## Focused QoS identity-map diagnostic

`cmd/mw2-qos-patcher` now replaces only the verified calls at `0x002fa2c0`
(`sub_CB538`) and `0x002fa300` (`CommitCandidateQoSResult`). The wrappers preserve
the original calls and emit one 96-byte version-6 record to
`/dev_hdd0/tmp/qos-map.bin`. A failed identity map writes immediately; a
successful map waits for the commit call and records both the pre-commit and
post-commit candidate fields. The record contains the completed QoS 8-byte
session/security ID, mapped index, party object and candidate-array pointers,
commit arguments, candidate active byte, `+0x44/+0x48/+0x4C` before and after,
and the commit return value. `mw2-inspect -qos` decodes version-6 records.

The diagnostic was built from `files/default_mp_tu0_clean.elf` without modifying
that source. Its SHA-256 remains
`5ecae7aebdffa8b5aa62f087a81f1b9c20f9c4b3dbdc4d41c2c00e65f1072041`.
The first generated build crashed at `0x007d6de0` after a successful QoS probe.
RPCS3 reported LR `0x0070944c`, identifying the commit wrapper call at offset
`0x1c8`. The patcher had relocated the original commit branch at offset `0x1f4`
instead; consequently the unrelocated instruction at `0x1c8` retained the
original relative displacement and resolved from the code cave to the crash
address. The relocation now patches `wrapperVMA+0x1c8` to `0x000cd998`, and the
focused test validates every wrapper call at its exact instruction offset.

Corrected generated artifacts:

- `files/default_mp_tu0_qos_map_fixed.elf` — SHA-256
  `d9f2aea3c4b93cfe0f37eb1043c62f5a635b4e00c2ef33dd5584f46621adef2c`
- `files/default_mp_qos_map_fixed.self` — SHA-256
  `ad415d3becd51edb8c0af3293e1e0d3b696c9e72dfc95c4690f5c61c45987989`
- `files/default_mp_qos_map.self` and the RPCS3-installed
  `default_mp.self` now contain that same corrected SELF.

The SELF was decrypted after packaging and matched the corrected ELF exactly.
Before the RPCS3 run, delete any stale
`/dev_hdd0/tmp/qos-map.bin`, and repeat the physical-PS3/RPCS3 matchmaking test.
Retrieve the resulting file and decode it with:

```text
go run ./cmd/mw2-inspect -qos PATH/TO/qos-map.bin
```

Interpretation is direct: `map_index=-1` indicates that the completed QoS ID did
not match a party candidate and points back to session/security-ID serialization
or selection; a nonnegative map with `commit_result=0` indicates candidate-state
rejection; `commit_result=1` with unchanged `post_total=-1` would indicate a
wrapper/layout error, while populated post fields would move the investigation
to the subsequent cleanup/selector scheduling.

`go test ./...`, `go vet ./...`, `gofmt -d`, and `git diff --check` pass.

## Live selector candidate-array snapshot

`cmd/mw2-qos-patcher` now also replaces the verified
`SelectJoinablePartyCandidate` call at `0x000d6924` inside the live party pump
`sub_D5C40`. The transparent wrapper calls the original selector first, then
writes `/dev_hdd0/tmp/qos-selector.bin`. Its `QSE1` version-1 snapshot contains
the party object pointer, candidate-array pointer, candidate count, and up to 32
complete 80-byte candidate entries. The wrapper lives in verified zero padding
at VMA `0x00709b00` and preserves LR, TOC, condition state, the selector return
value, and the original party-object argument. This directly reveals whether the
party pump sees no candidates, an inactive/unresolved entry, or a populated
candidate whose metric should be selectable.

The selector snapshot format is big-endian: 16-byte header (`QSE1`, version,
record count, party pointer, candidate-array pointer, candidate count) followed
by the captured 80-byte entries. Before the next RPCS3 run, delete stale
`/dev_hdd0/tmp/qos-selector.bin` along with `qos-map.bin`; retrieve both files
after the matchmaking attempt. Tests validate the selector callsite context,
wrapper relocation targets, 80-byte copy loop, output path, and cave bounds.
The verified TU0 selector context ends with branch `0x482305CD`; the patcher now
extends the executable LOAD through the complete selector wrapper so SELF
packaging preserves it. Generated `files/default_mp_tu0_qos_selector.elf` and
`files/default_mp_tu0_qos_selector.self`, with a successful decrypted-SELF
round-trip comparison against the patched ELF.

`go test ./cmd/mw2-qos-patcher` passes.

The 2026-09-01 RPCS3 run reached the selector call but crashed at unmapped CIA
`0x00c30af0`, with LR `0x00709c04` and stack frames through wrapper
`0x00709b20` and selector return `0x000d6928`. Inspection of the generated ELF
showed that the selector wrapper's filesystem relocations were four bytes late
for `cellFsOpen`, eight bytes late for `cellFsWrite`, and eight bytes late for
`cellFsClose`. They overwrote the TOC restore, `cellFsWrite` argument load, and
selector-return restore respectively; the first corrupted TOC caused the
filesystem thunk to branch to `0x00c30af0`.

The relocations are corrected to wrapper offsets `0x100`, `0x120`, and `0x12c`.
Regression tests now assert the neighboring TOC and argument/return-preservation
instructions so a branch cannot silently replace them again. `go test
./cmd/mw2-qos-patcher`, `go vet ./cmd/mw2-qos-patcher`, and `git diff --check`
pass. New round-trip-verified artifacts are
`files/default_mp_tu0_qos_selector_fixed.elf` (SHA-256
`135af486b0a96f81ea0e990303c7066d08c20d4baa425a8a7cc7ed26806f648c`)
and `files/default_mp_tu0_qos_selector_fixed.self` (SHA-256
`241ee293dce06ef313535265a57732d2aedaedcf6c949196cd6af1ad52a010d4`).
The 2026-09-01 RPCS3 retest reached `cellFsWrite` but froze with `r5=0xd000e208` instead of the selector snapshot size. The wrapper kept that size only in volatile `r10`; `cellFsOpen` legitimately clobbered it before the write. The selector wrapper now spills the capped byte count to `0x44(r1)` before building the snapshot and reloads it into `r5` immediately before `cellFsWrite`. The copy loop also decrements `r10` directly, avoiding the previous temporary-register dependency. Regression tests assert both spill/reload instructions, and `go test ./...` passes. Generated `files/default_mp_tu0_qos_selector_size_fixed.elf` (SHA-256 `98c957b617ee5299e88717acc2507d25d8e4b84b4938e71248eecf313f401514`) and `files/default_mp_tu0_qos_selector_size_fixed.self` (SHA-256 `cc892668bb131aa2bbdf212f1a0157b632dadbd40ad7702a899b88efad43ade6`); the patcher verified the decrypted SELF byte-for-byte against the ELF. The malformed 3.25 GiB `/dev_hdd0/tmp/qos-selector.bin` was removed and the new SELF was deployed to `dev_hdd0/game/BLUS30377/USRDIR/default_mp.self`; its installed SHA-256 is `cc892668bb131aa2bbdf212f1a0157b632dadbd40ad7702a899b88efad43ade6`. An RPCS3 matchmaking retest is still required.

## Patched SELF build runbook

`docs/BUILD_PATCHED_SELF.md` documents the repeatable patch-and-sign workflow.
It requires `files/default_mp_tu0_clean.elf` to remain an immutable input, uses
distinct ELF and SELF output paths, packages with the tools and key data under
`files/self`, and retains the patcher's decrypted-SELF byte-for-byte verification.

## Reference material

- Local analysis inputs, not committed: the supplied retail PCAP and
  `default_mp.elf`
- Playlist fixture: `playlists.info`
- Focused documents:
  - `docs/demonware-flow.md`
  - `docs/demonware-auth.md`
  - `docs/demonware-lsg.md`
  - `docs/demonware-ip-discovery.md`
  - `docs/demonware-peer-qos.md`
  - `docs/demonware-peer-dtls.md`
- `docs/demonware-lobby-messages.md`
- `docs/demonware-storage-playlists.md`

- World at War ELF Demonware flowchart (can cross-reference with CoD4 PDB loaded in IDA MCP): https://primetime43.github.io/CoD-Research/World-at-War-COD5/#/DemonWare/Flow-Charts?id=blus30192-demonware-elf-call-flow-charts
