# MW2 PS3 retail matchmaking protocol

This note records the service-5 layouts recovered directly from
`default_mp.elf` and the exact implementation boundary in this repository. It
separates binary proof from cross-version corroboration and from behavior that
still needs a live RPCS3 run.

## Confidence and authority

The MW2 ELF is authoritative for this client build. The supplied Ghosts
executable/PDB and preserved public implementations corroborate stable task
numbers, but they use different service IDs and title-specific objects. Their
wire layouts are not imported where the MW2 ELF differs.

| Finding | Confidence |
|---|---:|
| service ID `5` | >99% |
| ops `1` create, `2` update, `3` delete, `4` find by ID, `5` find sessions | >95% |
| exact op-5 request layout and zero-result reply | >99% |
| zero results are accepted by the client container | >95% |
| op-1/op-2 nine-I32 extension and nonempty-result echo | >99% |
| meanings and order of all seven op-5 query I32s | >95% |
| compatibility equality for unranked/ranked game type | >95%; slot-pool selector must match |
| game mode, netcode, playlist version, and performance comparison | disproven by successful retail two-PS3 capture; intentionally not implemented |
| map-pack comparison | unproven; intentionally not implemented |
| unranked/ranked slot-pool condition (`openPrivate`/`openPublic >= requiredFreeSlots`) | >95% |
| 25-byte common-address layout and create-to-result echo | >95% |
| encrypted two-client storage-to-candidate server lifecycle | >95%; automated |
| live RPCS3 op-1/op-2/op-3/op-5 request parsing | confirmed on 2026-07-29 |
| live RPCS3 zero-result op-5 response acceptance | confirmed on 2026-07-29 |
| live RPCS3 private-slot candidate search | request confirmed; corrected nonempty result awaiting retest |
| live RPCS3 two-client join/gameplay | not yet established |

The retail PCAP confirms record framing but cannot decrypt the lobby payload
without the unavailable production session secret. The 2026-07-29 emulated run
reached storage op `5` and matchmaking operations `1`, `5`, `2`, and `3`,
confirming the request layouts and zero-result operation-5 reply live. That run
advertised only private slots (`openPublic = 0`, `openPrivate = 8`), so it did
not establish a nonempty candidate result or the peer handoff.

## Common request encoding

The encrypted record's raw message type is service `5`. Its task payload is:

```text
1 bit       type-check-present = 1
typed u8    operation ID
arguments
raw 5 bits  zero terminator
zero bits   byte/block padding
```

Typed fields use a five-bit LSB-first tag followed immediately by LSB-first
payload bits. Multibyte scalars are little-endian on the wire.

```text
U8    tag 3
I32   tag 7
U32   tag 8
U64   tag 10
Blob  tag 19
```

A blob is:

```text
tag 19
typed U32 byte length
that many raw bytes
```

Primary functions are bit-buffer constructor `0x003d24f0`, tag writer
`0x003d3300`, payload writer `0x003d2200`, and task wrapper/terminator
`0x003e6f60`.

## Exact task requests

All five recovered requests begin their argument body with typed `U8(0)`.

### Operation 1: create session

```text
typed U8  0
bdMatchMakingInfo
typed I32 title field 0
typed I32 title field 1
typed I32 title field 2
typed I32 title field 3
typed I32 title field 4
typed I32 title field 5
typed I32 title field 6
typed I32 title field 7
typed I32 title field 8
raw U8    0
raw U8    0
raw 5-bit zero terminator
```

### Operation 2: update session

The wire shape is identical to operation `1`.

The title serializer at `0x003253c0` first calls the base serializer at
`0x003e2a10`, then writes object offsets `+0x24` through `+0x44` as nine
typed I32s. The live op-1/op-2 object installs that serializer in virtual slot
`+8`; stopping after the base object is therefore an incomplete decode.

### Operation 3: delete session

```text
typed U8  0
Blob[8]   session ID
raw 5-bit zero terminator
```

There is no two-octet object suffix on operation `3`.

### Operation 4: find by session ID

The dedicated builder uses the same argument shape as operation `3`.
An exhaustive reference scan found no MW2 title call site for this builder; its
only reference is its own OPD descriptor. The common reply envelope accepts op
`4` and a result count, but the record class is chosen by the absent caller,
not by the envelope parser. Therefore neither the found-record body nor the
retail not-found policy can be established above 80% confidence. A
transaction-zero success with count zero would encode as
`0a0000000000000000010000000c020400000000`, but the server intentionally does
not advertise op `4` support from that envelope alone.

### Operation 5: find sessions

```text
typed U8   0
typed I32  query type = 2
typed I32  maximum results = 50
typed I32  unranked flag = !xblive_rankedmatch
typed I32  selected playlist/game-mode ID
typed I32  netcode/protocol version
typed I32  owned map-pack flags
typed I32  playlist version
typed I32  required free slots in the selected pool
typed I32  performance/skill value
raw U8     0
raw U8     0
raw 5-bit  zero terminator
```

The query constructor initializes the first six fields to `INT_MAX` and the
performance field to zero. Those values are constructor “unset” defaults, not
proven backend wildcards. The sole public-search path overwrites all seven
before transmission. The constructor-default vector, excluding raw service ID
`5`, is:

```text
47c100380200000047060000e0fcffffff9dffffffbff3ffffff
77feffffffceffffffdff9ffffff3b00000000000000
```

The actual public-search call at `0x00319e60` overwrites all seven values with
live inputs before sending. Raw PPC at `0x00319ef8..0x00319f10` proves this;
requiring the constructor defaults would reject the retail request.

The direct producer-to-wire trace establishes this order:

| Query field | Object offset | Recovered meaning | Primary MW2 evidence |
|---|---:|---|---|
| `q0` | `+0x10` | `!xblive_rankedmatch` / unranked flag | dvar load and inversion at `0x00305ca4..0x00305cc8`, store at `0x00319efc` |
| `q1` | `+0x14` | selected raw playlist/game-mode ID | playlist-index helper `0x00259fa0`, store at `0x00319ef8` |
| `q2` | `+0x18` | netcode/protocol version | producer `0x002854b0`, store at `0x00319f00` |
| `q3` | `+0x1c` | owned map-pack flags/mask | producer `0x000cf938`, store at `0x00319f04` |
| `q4` | `+0x20` | playlist version | producer `0x00258410`, store at `0x00319f08` |
| `q5` | `+0x24` | required free slots in the `q0`-selected pool | party counters `0x000c3ce0` / `0x000c3d28`, store at `0x00319f0c` |
| `q6` | `+0x28` | performance/skill value | global load `0x00305e90`, store at `0x00319f10` |

The first two values are easy to reverse accidentally: the wrapper stores
caller `r5` (`!ranked`) in `q0`, then caller `r4` (playlist) in `q1`.

The client and the 2026-07-30 two-client trace prove that `q0` selects the slot
pool used by `q5`: nonzero (`!ranked`, an unranked search) requires enough
`openPrivate` slots, while zero (ranked) requires enough `openPublic` slots.
Both live searches carried `q0=1`; their hosts advertised `openPrivate=8` and
`openPublic=0`, exposing the previous public-only filter. The vanilla-client
crash capture shows that returning sessions across different `q1` game-mode and
`q2` netcode values sends incompatible clients into peer
traversal. The directory therefore requires exact equality for game type, game
mode, netcode version, map-pack flags, and playlist version before applying the
slot test. Performance remains unfiltered because no retail comparison rule for
`q6` is proven.

Primary functions are common builder `0x003e16a0`, base query serializer
`0x003de268`, and derived query serializer `0x00325850`.

## `bdMatchMakingInfo`

Operations `1` and `2` serialize:

```text
Blob[25]  serialized common address
Blob[8]   session/security ID
Blob[16]  security key
I32       open public slots
I32       filled public slots
I32       open private slots
I32       filled private slots
```

The serializer is `0x003e2a10`; the inverse base parser is `0x003e2e08`.

Join/leave paths at `0x00307298` and `0x00306f68` prove that the first and
third values are open-slot counts: they move one slot between each
open/filled pair.

The common-address blob is:

```text
offset 0x00  local/private IPv4+port 0 (6 bytes)
offset 0x06  local/private IPv4+port 1 (6 bytes)
offset 0x0c  local/private IPv4+port 2 (6 bytes)
offset 0x12  public/external IPv4+port (6 bytes)
offset 0x18  NAT type (1 open, 2 moderate, 3 strict)
```

Each address is four IPv4 octets followed by a little-endian port. Unused
local slots use sentinel `00 ff 00 ff 00 00`. The server does not need to
reconstruct this object: it preserves the host's exact 25 bytes and returns
them unchanged in search results.

The strict reusable codec in `internal/peerproto/commonaddr.go` validates the
three local slots, public endpoint, and NAT enum (`1` open, `2` moderate, `3`
strict). Local slots cannot contain a gap: once the sentinel appears, all
remaining local slots must also be sentinel.

The traversal identifier is the first four bytes of Tiger-192 over exactly the
six wire bytes of the effective address. The client chooses the public endpoint
when present, otherwise local slot zero, otherwise the sentinel. During direct
traversal it tries the host's populated local endpoints in order and then its
public endpoint; it does not perform a same-subnet comparison first. A
type-`0x0d` receiver verifies the identifier and replies to the actual UDP
sender, so a same-LAN candidate can work with the exact common address already
echoed by the central directory.

## Reply envelope

Raw outer reply message type is `1`. The matchmaking body is bit-packed:

```text
typed U64  transaction value
typed U32  error
if error == 0:
    typed U8   echoed operation ID
    typed U32  result count for result-producing ops 1, 4, and 5
    results
```

The remote dispatcher at `0x003e6c08` consumes the leading typed U64 and
associates replies with pending tasks FIFO. This client does not use the U64
value to select a task.

The matchmaking result parser at `0x003e1840` reads the error, validates
result-producing operations `{1,4,5}`, reads exactly one typed U32 count, and
delegates the remaining buffer to the registered result object. This is a
MW2-specific result path; a cross-version two-count envelope must not be
imported here.

### Operation-1 result

A functional create response uses count `1` followed by:

```text
Blob[8]   generated session ID
Blob[16]  generated security key
```

Parser `0x003e3c88` accepts zero or one result. Completion `0x0031a538`
installs the exact 8-byte ID and 16-byte key into game state.

### Operation-2 and operation-3 results

Update and delete are mutation-only replies. On success they contain the
transaction, zero error, and echoed operation ID, with no result-count field.
At transaction zero their exact bodies are:

```text
op 2: 0a0000000000000000010000000c01
op 3: 0a0000000000000000010000008c01
```

The operation-2 request identifies its record through the embedded base
Blob[8] session ID. Operation 3 carries that same ID as its sole object
argument.

### Operation-5 result

Each nonempty result contains the base `bdMatchMakingInfo`, followed by nine
typed I32 fields. Parser `0x00325c38` requires all nine. They are the same
ordered title-extension values sent by the host's op-1/op-2 serializer, so a
directory can preserve and echo them without assigning speculative names.
Completion `0x0031aa58` reads only the base object and never reads offsets
`+0x24..+0x44`; their values do not affect candidate construction on this
client path. Container `0x004ef168` accepts at most 50 results.

An exhaustive write-reference audit found that this build normally leaves title
fields `0..7` at their constructor value zero. Title field `8` (`+0x44`) is the
current performance value: `0x003079fc..0x00307a00` stores it for create, and
the same global is passed as query `q6` at `0x00305e90`. The successful retail
two-PS3 capture confirms the wire correspondence: one host advertised field `8`
as `1000` and searched with `q6=1000`, while the other advertised field `8` as
`0` and searched with `q6=0`. Both operation-5 replies still contained both
sessions, disproving exact performance equality as retail directory policy.

Zero results are explicitly valid. The exact implemented body at transaction
zero is:

```text
0a0000000000000000010000008c020400000000
```

Decoded:

```text
typed U64 transaction = 0
typed U32 error = 0
typed U8  operation = 5
typed U32 result count = 0
```

Container `0x004ef168` skips its element loop, and completion `0x0031aa58`
continues through the no-sessions path.

## Current implementation

`internal/auth/lsg_matchmaking.go`:

- validates exact requests for operations `1` through `5`;
- rejects malformed sizes, nonzero reserved/suffix/terminator fields, and
  unsupported query variants;
- accepts the retail operation-5 type-2/max-50 layout with all seven recovered
  query values;
- creates a session with a nonzero cryptographically random Blob[8] ID and
  Blob[16] key;
- atomically updates and deletes records by the embedded/generated ID;
- binds mutation rights to the LSG connection that created the record;
- caps the process-wide directory at 4096 sessions;
- shares one mutex-protected directory across retail LSG connections; and
- emits exact zero/nonempty operation-5 results in deterministic creation order;
- includes the requester's own session, orders eligible sessions by creation, and
  gives both clients the same directory snapshot once reciprocal advertisements
  exist. A delete/recreate receives a fresh position rather than retaining its
  connection's former priority.

Creation ordering is used only to keep returned snapshots deterministic and put
the earliest advertisement first. The successful retail two-client flow is
self-inclusive: both clients receive both advertisements before peer selection.

The query meanings are recovered. The compatibility policy requires the echoed
unranked/ranked game type to match, uses it to choose private or public slots,
and applies the directly justified free-slot requirement. The successful retail
two-PS3 capture returned both sessions even though the peers differed in game
mode, netcode version, playlist version, and performance, disproving equality
filters for those fields. Map-pack comparison remains unproven, so the directory
does not invent one. This is deliberately no narrower than the observed retail
backend.

Operation 4 remains unsupported until its exact result template and live use
are established.

An active host forces operation `2` every `180000` ms. Dirty changes from
create, join, or leave are coalesced for at least `3000` ms, and a failed
update re-dirties an active record for another attempt. The exact backend
expiry duration is not present in the client.

The compatibility directory does not invent a time-based lease. It retains a
session until operation `3` or until its authenticated LSG connection closes,
at which point emulator cleanup reclaims every record owned by that connection.
Authenticated LSG traffic uses a separate five-minute idle deadline instead of
the shorter general handshake/frame timeout. It exceeds the proven 180-second
refresh interval with two minutes of grace. This is connection-resource policy
rather than a recovered backend session lease. Any future stale-record policy
must retain that evidence boundary.

Normal host teardown attempts operation `3`; delete failure is not retried.
Request bodies contain no explicit principal/owner field, and search results
disclose the Blob[8] ID. To prevent one authenticated seeker from mutating
another host in the emulator, update/delete are additionally restricted to the
LSG connection that created the record. This is an explicit hardening policy,
not a claim about historical Demonware principal bookkeeping. Connection-close
cleanup ensures an abandoned record does not become permanently unmodifiable.

The fixed 4096-record cap similarly prevents unbounded process memory growth.
Capacity exhaustion returns a normal service error, and connection-close
cleanup releases records even when normal operation-3 teardown was not
delivered. It is emulator policy, not a recovered production population limit.

`internal/auth/lsg_matchmaking_test.go` contains golden bit vectors, field
round-trips, malformed-query tests, exact mutation/nonempty replies, and a
direct shared-directory lifecycle. `internal/auth/full_flow_test.go` drives two
encrypted LSG clients through storage operations `8`/`5`, then create, find,
update, find, delete, and an empty final find while asserting the exact
candidate tuple. Store tests cover deep copies, deterministic capping,
concurrency, and race detection.

## Next live gates

1. Confirm corrected storage op `8` advertises byte size `205`.
2. Observe storage op `5`, serve the exact blob, and confirm playlist parsing.
3. Observe an actual service-5 op-5 payload and record its seven live values.
4. Confirm the client accepts both zero-result and nonempty-result responses.
5. Run two clients through create -> find -> update -> delete against the
   shared directory and confirm both clients receive the same self-inclusive,
   creation-ordered two-session snapshot before peer selection.
6. Capture the post-find peer QoS/traversal and secure-association flows
   described in `demonware-peer-qos.md` and `demonware-peer-dtls.md`, then
   complete a joined match.

The first action after a nonempty result is already statically identified:
completion `0x0031aa58` copies the Blob[8] ID, 25-byte common address, and
Blob[16] key into a candidate, calls router association `0x000cb1f0`, and then
passes candidates to `0x002fac00` ("Starting QoS probes"). That path calls
`0x00320680` to create/start QoS and enters the peer socket router. There is no
intervening central service-5 join RPC. The host client answers the peer
QoS/title handshake; later host state changes produce operation `2` slot-count
updates.

The supplied 62.655-second retail startup/lobby PCAP contains no traffic to a
candidate LAN/residential peer and no QoS request/reply pair. The separate
90.964-second `mw2 ps3 ingame.pcapng` trace does contain the post-find peer
phase: the first candidate-directed UDP packet is a type-`0x28` QoS probe at
frame 709 (`58.2509763`, `192.168.0.199:3074 -> 68.82.57.194:3074`), with
retries at frames 710-712 and a second probe transaction at frames 739-742.
Frame 1782 is instead a type-`0x0c` traversal acknowledgement. This packet
sequence corroborates the statically recovered
handoff and confirms that retail proceeds from the central directory result to
direct peer traffic without another central service-5 join RPC. The production
LSG payload remains encrypted and the ingame capture has TCP sequence gaps, so
the returned candidate tuple itself is not recoverable from these PCAPs.

The 2026-07-29 emulated trace reaches the same central request boundary but
returns zero candidates. The 2026-07-30 two-client trace clarifies why that was
incorrect: both queries carry `unranked = 1`, and both hosts advertise
`openPrivate = 8` with `openPublic = 0`. For this query the server must test the
private slot pool. The public-only filter suppressed otherwise eligible
candidates, so no candidate-directed `0x28`/`0x29` QoS or `0x0a`..`0x0d`
traversal datagram was sent. A fresh two-client run against the corrected
slot-pool selection is the next required live comparison.

Direct MW2 serializers and parsers establish the exact peer QoS and
NAT-traversal datagrams, HMAC input, and retry state above the implementation
threshold; see `demonware-peer-qos.md`. The complete live endpoint selection,
central introducer contract, and peer-DTLS confirmation remain pending. The
canonical peer-DTLS handshake itself is statically recovered in
`demonware-peer-dtls.md`.
