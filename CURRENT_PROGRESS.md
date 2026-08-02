# Current status of MW2 Demonware server emulation

_Last updated: 2026-08-01 after correcting service-17 raw-field endianness.
The server again delivered the physical PS3 session and RPCS3 completed direct
QoS, but the first version-2 diagnostic wrapper crashed before peer DTLS by
passing `r3 = 1` to `sub_CFF28`. The wrapper dispatch/register bug remains fixed
and deployed. Static review also found that operation-2 status/performance fields
were emitted little-endian even though the recovered MW2 result reader consumes
raw big-endian U32 values; the server and regression test now use the correct
byte order and require another live retest._

## Executive summary

The project gets MW2 on RPCS3 through dynamic Demonware authentication, the
encrypted Lobby Service Gateway (LSG) handshake, storage, and playlist loading.
The retail `playlists.info` has been retrieved, the storage flow works live, and
the game client accepts the emulated server's playlist. Two live clients now
find one another and complete direct traversal and QoS. Corrected performance
replies are accepted, and telemetry proves both clients pass the type-1 QoS gate.
The stable-ordering retest had the physical PS3 create first and RPCS3 create
second. The PS3 consistently received zero candidates while RPCS3 consistently
received exactly the PS3 session, including the correct common address, generated
session ID, security key, slot counts, and all nine attributes. Traversal and QoS
completed repeatedly with valid replies, but no peer-DTLS Init followed. The PS3
deleted its session near the end and did not recreate it; only then did RPCS3
correctly fall to zero candidates. The next live task is therefore to retest the
corrected service-17 raw-field endianness with the fixed diagnostic wrapper,
then use its counters to reverse
the accepted-candidate transition around `sub_CFF28`; operation-5 ordering
should not be changed again.

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

| Phase                               | Status                                                                                                          | Evidence / notes                                                                                                                                                                                                                                                                                                                                            |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Listener startup                    | Working                                                                                                         | Auth/LSG TCP and primary discovery UDP coexist on `3074`; alternate-source UDP `3075`, experimental lobby, and HTTP listeners also start.                                                                                                                                                                                                                   |
| Dynamic authentication              | Working in prior live runs                                                                                      | A fresh session key, game ticket, and LSG ticket are generated per connection.                                                                                                                                                                                                                                                                              |
| RPCN key extraction                 | Working in prior live runs                                                                                      | The LSG key is found relative to the `RPCN` marker rather than a brittle absolute offset.                                                                                                                                                                                                                                                                   |
| Encrypted retail LSG                | Working in prior live runs                                                                                      | Client requests decrypt and validate; replies use the observed 3DES-CBC record framing.                                                                                                                                                                                                                                                                     |
| Storage operation `8`               | Working live                                                                                                    | Returns leading type-checking bit `1`, then the proven publisher results `messageoftheday.info`, TU0 `playlists.info`, and title-update `playlists.patch3`, each with actual byte size and `bdFileInfo`. A speculative `mp/mappack.info` entry remains removed.                                                                                           |
| Storage operation `7`               | Implemented                                                                                                     | Returns a successful empty outer result count.                                                                                                                                                                                                                                                                                                              |
| Storage operation `5`               | Working live                                                                                                    | Consumes typed `u8(0)` before the advertised opaque ID, then returns actual buffer size, matching `bdFileInfo`, and the raw typed blob. The client accepts the served playlist.                                                                                                                                                                                |
| MOTD prerequisite                   | Implemented                                                                                                     | Two binary state initializers request `messageoftheday.info`; the consumer accepts at most `0x100` bytes of plain text. `MW2_MOTD` overrides the built-in welcome text.                                                                                                                                                                                         |
| Bundled `playlists.info`            | Retail-parser valid; 95% confidence                                                                             | ID `0` is feeder-visible, alias/script `dm` resolves, the weight-100 entry counts, and solo bounds pass selection.                                                                                                                                                                                                                                          |
| Docker playlist packaging           | Fixed in the working tree                                                                                       | The final image copies the fixture to `/playlists.info` and sets `MW2_PLAYLISTS_FILE`.                                                                                                                                                                                                                                                                      |
| Stats                               | Placeholder only                                                                                                | The observed retail request is service `4`, operation `4`; the server currently returns an empty success.                                                                                                                                                                                                                                                   |
| Groups                              | Set/clear serializers recovered; matchmaking performance call was previously misclassified                     | Service `17`, operation `2` in the live matchmaking path is `bdMatchMaking::getPerformanceValues`, not set-groups. The actual group serializers remain identified at `0x003e4758` and `0x003e4638`.                                                                                                                                                           |
| Bandwidth                           | Two-phase bootstrap working live                                                                                | Service `18/1` returns the exact 51-byte request result, accepts five 512-byte UDP uploads on the primary NAT socket, then returns the 29-byte finalize result. The current two-client run completed this phase on both clients.                                                                                                                             |
| Retail matchmaking op `5`           | Working live                                                                                                    | Both clients repeatedly receive the other client's candidate. The recovered unranked flag correctly selects private slots; nonzero uses private slots and zero uses public slots. Unknown retail comparisons are not guessed.                                                                                                                             |
| Retail matchmaking lifecycle        | Working through candidate QoS and performance/session update; lobby handoff unresolved                          | Two live clients create/find candidates, complete direct NAT/QoS, accept one performance result, and update their sessions from private `8/0` to `7/1`. They then restart searching rather than beginning peer DTLS.                                                                                                                                       |
| UDP public-address/NAT discovery    | Working live                                                                                                    | Exact v2 public-address and NAT-classification exchanges complete, including primary/alternate-source replies.                                                                                                                                                                                                                                              |
| Peer QoS packet codec               | Working live                                                                                                    | Live clients exchange 17-byte `0x28` requests and 18-byte zero-payload `0x29` replies. All multibyte values are little-endian; the reply data length is a little-endian `u32`.                                                                                                                                                                               |
| Peer NAT traversal and introducer   | Direct `0x0d`/`0x0c` traversal working live; legacy `0x0a` relay remains safety-gated                           | Both clients exchange exact 29-byte type-`0x0d` requests and type-`0x0c` acknowledgements over LAN and the advertised external route. The trusted-lab introducer relay still accepts only strict type `0x0a` packets and changes only the type to `0x0b`.                                                                                              |
| Peer DTLS codec                     | Recovered directly from the ELF; not reached live                                                               | No peer-DTLS packet follows the successful traversal/QoS/performance sequence. Canonical Init/InitAck/CookieEcho/CookieAck/Error packets remain 16/38/177/114/15 bytes.                                                                                                                                                                                     |
| Playlist parsing / lobby population | Playlist accepted; lobby population unresolved                                                                  | Both clients select playlist `1`, advertise sessions, and search successfully, but return to candidate search after QoS instead of joining/populating a shared lobby.                                                                                                                                                                                        |
| Runtime discovery telemetry         | Corrected in the working tree                                                                                   | Packed operation IDs are decoded before logging; unsupported service/operation pairs are explicitly warned while still receiving an error reply.                                                                                                                                                                                                            |

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
`openPublic >= requiredFreeSlots`. This is confirmed by the latest two-client
trace: both searches carried `unranked=1`, both hosts advertised private slots,
and the public-only filter incorrectly returned zero. The historical comparisons
for the remaining five fields plus performance remain server-side and are
intentionally not guessed. Full schemas and confidence boundaries are in
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

Further TU0 analysis corrects the meaning of the selected 80-byte entry's
`+0x44` field. `QoSEntry_Init` (`0x2FC4A0`) initializes it to `0`, not `-1`.
`CommonAddr_ComputeHash` (`0x281340`) computes the canonical 32-bit hash from a
CommonAddr; both establishment paths store that result into `+0x44` at
`0x301E9C` and `0x302368`. `SecureAssoc_FindByEntryHash` (`0x2FD288`) then reads
`+0x44` as its lookup key, and `SecureAssoc_CreateForEntry` (`0x2FD408`) copies
it into the newly allocated association object. Consequently the cleanup check
`+0x44 == -1` means "invalid/unassigned lookup key," while `0` is only the
pre-assignment initializer. If phase 2 never obtains a nonzero/non-`-1` value,
the failure is before secure-association lookup: the selected entry never
receives the CommonAddr hash. If it does obtain a hash, the next diagnostic
boundary is `SecureAssoc_FindByEntryHash`/`SecureAssoc_CreateForEntry`, not the
operation-5 reply codec.

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
   version-2 telemetry now clears.
4. Once peer DTLS begins, compare the live Init/InitAck/CookieEcho/CookieAck flow
   with the recovered codec and trace the first lobby message.
5. Preserve this run as the baseline: stable asymmetric discovery, operation-2
   slot/attribute updates, and repeated direct `0x0d`/`0x0c` plus `0x28`/`0x29`
   exchanges succeeded, accepted QoS cleanup completed normally, but no peer
   DTLS started.

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
sites branch to wrapper VMA `0x709280`. It has not yet been resigned or deployed.

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
