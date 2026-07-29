# Demonware storage and `playlists.info`

This document describes the MW2 PS3 retail storage path confirmed from
`default_mp.elf`, the current server implementation, and the bundled fixture.
It separates statically proven wire behavior from behavior that still needs a
live RPCS3 capture.

## Current verification state

Confirmed statically and covered by repository tests:

- MW2 initializes `messageoftheday.info` publisher-download states before the
  `playlists.info` state, so both files must be present in the publisher
  directory;
- every received typed task payload starts with a one-bit type-checking marker
  which the client consumes before any five-bit type tag;
- storage is retail service `10`;
- operation `8` lists publisher files;
- operation `5` retrieves the selected file ID;
- operation-8 results contain an outer result count and a per-file typed size;
- the proven unfiltered publisher directory contains exactly
  `messageoftheday.info` followed by `playlists.info`; the speculative
  `mp/mappack.info` entry has been removed pending direct retail proof;
- operation `5` begins with a typed destination-buffer size and has no outer
  result count on the wire;
- both paths use the same seven-field `bdFileInfo` metadata serializer;
- the file data is a tag-19 blob with a nested typed `u32` length;
- the operation-8 completion loop selects a result by exact filename equality,
  copies only that result's `u64` file ID, and immediately starts operation
  `5`;
- the downloaded byte count must be at most `0x20000`, after which the game
  passes the raw buffer to the playlist-text parser;
- the bundled `playlists.info` is a retail-parser-valid version-504
  playlist whose only row is visible and solo-selectable.

Still pending live verification:

- the corrected operation-8 reply with both required publisher files;
- an observed operation-5 request for `messageoftheday.info`;
- an observed operation-5 request for `playlists.info`;
- successful download and client parsing of the bundled bytes.

Do not treat the current static proof and unit tests as full live completion.

## Retail playlist flow

The recovered MW2 call chain is:

```text
storage operation 8
    -> find messageoftheday.info
    -> storage operation 5 with its opaque ID
    -> consume at most 0x100 bytes as MOTD text

storage operation 8
    -> receive publisher-file metadata
    -> find exact filename "playlists.info"
    -> read its stable u64 file ID
    -> storage operation 5 with that ID
    -> receive metadata and raw text blob
    -> parse the playlist locally
```

The operation-8 completion loop at `0x00322aa8..0x00322bfc` calls the filename
getter (`0x004de420` -> `0x003ec8c0`), compares it with the requested filename,
then calls the file-ID getter (`0x004de430` -> `0x003ec898`) only on equality.
The getters return `bdFileInfo + 0x28` and the `u64` at `+0x08`,
respectively. The selected ID is stored at fetch-state offset `+0x10`; wrapper
`0x00322cd8` then calls `0x00322848`, which starts operation `5` with only that
ID.

No timestamp, owner, privacy flag, or other neutral metadata field is read in
this transition. There is also no local cache/version comparison in this
two-stage path. Exact filename equality plus a successful operation-8 result
is the gate to operation `5`.

The same state machine is used for `messageoftheday.info`. Initializers
`0x0030a748` and `0x0030a788` create MOTD states; `0x0030a7c8` creates the
playlist state. The MOTD consumer at `0x0030b1f0` provides a `0x100`-byte
buffer, trims CR/LF, and consumes the downloaded bytes as text. Consequently,
the publisher listing must not contain only `playlists.info`.

The payload is not JSON, a database, or a compressed container. The download
contains raw playlist text bytes; the bundled fixture is ASCII.

## Bit-packed typed encoding

Storage requests and replies use the LSB-first bit serializer. A five-bit type
tag is immediately followed by its value, so most fields are not byte-aligned.

Relevant tags:

|  Tag | Type                  |
| ---: | --------------------- |
|  `0` | terminator            |
|  `1` | bool                  |
|  `3` | `u8`                  |
|  `6` | `u16`                 |
|  `8` | `u32`                 |
| `10` | `u64`                 |
| `16` | NUL-terminated string |
| `19` | blob                  |

The common successful logical-reply prefix is:

```text
raw u8   message type = 1
raw bit  type-checking-present = 1
typed u64 transaction ID
typed u32 error code = 0
typed u8  operation ID
```

The raw message-type byte is added once. Do not prepend storage service `10` to
a server task reply. The marker is the first bit of the task payload, not a
second message byte.

This marker is mandatory. Incoming lobby messages construct a type-checked
`bdBitBuffer` at `0x003d2be8`; `0x003d2810` consumes the first payload bit into
the buffer's type-checking flag. If it is omitted, the low zero bit of the
first `u64` tag (`10`) is consumed instead. The generic task parser then skips
type tags and reads every field one bit out of alignment.

## Operation 8: list publisher files

The observed no-filter request is logically:

```text
raw u8   service = 10
raw bit  type-checking-present = 1
typed u8 operation = 8
typed u8 value = 0
typed u32 offset = 0
typed u16 maximum results = 100
optional typed string filename filter
raw 5-bit terminator = 0
zero padding to the current byte
```

The corrected successful reply is:

```text
raw u8   message type = 1
raw bit  type-checking-present = 1
typed u64 transaction ID
typed u32 error code = 0
typed u8  operation = 8
typed u32 result count = N
repeat N times:
    typed u32 file size
    bdFileInfo
```

The first `u32` is the outer result count. The next `u32` is not
`totalNumResults`: it is the byte size associated with that file.

Static evidence:

- dispatcher `0x003ecf18` reads the outer count for operations `7` and `8`;
- result handler `0x003eb4a8` reads one typed `u32` before every metadata
  object;
- after `bdFileInfo` deserialization, `0x003eb4a8` calls setter `0x003ec8d8`;
- that setter stores the value at object offset `0xa8`, the file-size field.

The unfiltered publisher directory contains `messageoftheday.info` followed by
`playlists.info`. Each result carries its own exact runtime byte size. Exact
filename filters and offset/maximum pagination select a subset of this
directory.

## Operation 5: get publisher file

The request is:

```text
raw u8   service = 10
raw bit  type-checking-present = 1
typed u8 operation = 5
typed u64 file ID
raw 5-bit terminator = 0
zero padding to the current byte
```

The ID must be the stable ID returned with exact filename `playlists.info`.

The corrected successful reply is:

```text
raw u8   message type = 1
raw bit  type-checking-present = 1
typed u64 transaction ID
typed u32 error code = 0
typed u8  operation = 5
typed u32 destination-buffer size
bdFileInfo
typed blob:
    typed u32 byte length
    raw file bytes
```

Operation `5` has no outer result count on the wire. Dispatcher `0x003ecf18`
passes an implicit result count of one to handler `0x003ea690`. That handler
reads the leading typed `u32` and uses it to preallocate or grow the file-data
buffer through `0x003ec290`.

The blob's nested byte length is the authoritative count of raw bytes that
follow. The leading value is a destination-buffer capacity hint, not an
equality check. This implementation uses the canonical and safe encoding where
both values are the payload length; for the current bundled fixture, both are
`193`.

An extra typed `u32` before `bdFileInfo` is fatal: the metadata parser expects a
typed `u64` file ID next and rejects tag `8`.

## `bdFileInfo` wire order

Function `0x003eca78` consumes the metadata in this exact order:

```text
typed u64 file ID
typed u32 value 1
typed u32 value 2
typed bool flag 1
typed bool flag 2
typed u64 value 3
typed string filename
```

Neutral names are intentional where the exact MW2 semantic label is not needed.
The corresponding recovered object storage is:

| Object offset | Stored value                                       |
| ------------: | -------------------------------------------------- |
|        `0x08` | file ID                                            |
|        `0x10` | first `u32`                                        |
|        `0x14` | second `u32`                                       |
|        `0x18` | first bool                                         |
|        `0x1c` | second bool                                        |
|        `0x20` | trailing `u64`                                     |
|        `0x28` | filename buffer, 128 bytes                         |
|        `0xa8` | file size injected by the operation result handler |

The filename encoding is:

```text
5-bit tag 16
raw 8-bit filename bytes
raw NUL byte
```

There is no string-length field and no type tag per character. The client reads
until NUL with a 128-byte destination limit. The current Go `writeString`
implementation is correct for `playlists.info`.

For playlist bootstrap:

```text
file ID  = 0x1122334455667788
filename = "playlists.info"
file size = len(served bytes)
```

The other metadata fields are currently serialized as neutral zero/false
values. Static tracing proves they are not inspected by the
operation-8-to-operation-5 selector. The exact filename and stable file ID are
the fields that drive this transition.

## Blob and file limits

The blob layout is:

```text
5-bit tag 19
5-bit tag 8
32-bit byte length
exactly that many raw bytes
```

The application buffer limit is `0x20000` bytes. The server rejects empty files
and files larger than that limit.

The blob is not compressed. It is not JSON and it is not another Demonware
container. It is the literal playlist text.

Application consumer `0x0030b1f0` configures a `0x20000`-byte destination,
polls the two-stage fetch, rejects a returned size above `0x20000`, and calls
playlist parser `0x00258bf0` with the downloaded buffer. Fetch failures are
retried by `0x0030a5d8` with exponential delay capped at 60 seconds. A screen
that remains on “Fetching Playlists” is therefore consistent with an operation
that never reaches successful completion; it is not evidence that the text
format itself is wrong.

## Bundled `playlists.info`

The repository fixture contains:

- `version 504`;
- gametype `dm`, with English name and script;
- playlist `0`, with English name and description;
- ranked party-size settings;
- one weighted `mp_afghan,dm,100` entry.

The structural validator reports:

```text
PASS: version=504, gametypes=1, playlists=1, entries=1, bytes=<loaded length>
```

The retail parser and feeder establish more than structural validity:

- `FUN_00258bf0` accepts unsigned playlist IDs `0..23`;
- `FUN_002583c8` and `FUN_00259fa0` enumerate populated slot `0`, so ID `0` is
  not a sentinel;
- the entry parser at `0x00259d64..0x00259e88` increments the slot count only
  for a resolvable gametype alias and positive weight;
- alias `dm`, script `dm`, and entry `mp_afghan,dm,100` satisfy those checks;
- default unlock/DLC state plus `minparty 1` and `maxparty 1` passes
  `FUN_0025aa28` for a solo player.

Confidence that the fixture itself is valid for this retail client is 95%.
Confidence in the exact operation-8 filename-selection and operation-5 handoff
described above is greater than 99% from direct client control flow. This does
not prove the game has downloaded or applied the file in a live session.

## Current server implementation

`internal/auth/lsg_storage.go` currently:

- parses the observed operation-8 and operation-5 request fields;
- advertises stable IDs for `messageoftheday.info` and `playlists.info`, in
  that order;
- writes operation `8` as count -> actual size -> `bdFileInfo`;
- writes operation `5` as actual buffer size -> `bdFileInfo` -> blob;
- uses each selected file's same ID and filename in list/get replies;
- rejects unknown IDs, empty files, and files over `0x20000`.

The request parser consumes and logs the operation-8 selector, offset, maximum,
optional filename filter, and five-bit terminator. Offset/maximum pagination and
exact filename filters are applied to the two-file directory; a mismatched
filter, zero maximum, or offset at/after the directory length returns a
successful empty list. Full transport-block padding is left available for
diagnostics instead of being treated as another task field. Operation 5
likewise requires its five-bit terminator to be zero.

The final Docker image now:

```dockerfile
COPY --from=build /src/playlists.info /playlists.info
ENV MW2_PLAYLISTS_FILE=/playlists.info
```

This fixes the previous deployment state in which the scratch image contained
only the executable and operation `8` returned `bdErrorNoFile`.

MOTD and playlist downloads are implemented on the retail storage path. No
other publisher file is advertised without direct MW2 proof.

## Live evidence versus pending work

An older RPCS3 run received replies that encoded `1, 1` after the operation;
static analysis proves those values meant result count `1` and the incorrect
file size `1`. A later Linux run correctly returned one 193-byte canonical LF
fixture but still did not issue operation `5`. A fresh current-bandwidth run
then advertised MOTD, playlist, and a speculative `mp/mappack.info` entry and
repeated operation `8`; the unproven third entry has now been removed while the
statically established serializer remains unchanged.

The next live checkpoint is:

1. send operation `8` with count `2`, exact runtime sizes, and only MOTD then
   playlist metadata;
2. confirm the remote task completes;
3. capture operation `5` for the advertised MOTD ID and then playlist ID;
4. send each actual buffer size, matching metadata, and raw-byte blob;
5. confirm the client parses version 504 and advances.

## Related retail services

Storage progress must not be conflated with later bootstrap services:

- stats is retail service `4`; the observed request is operation `4`, and only
  an empty placeholder response exists;
- retail matchmaking is service `5`;
- create/update/delete and operation `5`'s exact zero/nonempty result objects
  are implemented from direct client analysis against shared retail-LSG state;
- operation `4`, exact search-filter comparisons, and live two-client
  confirmation remain pending;
- the experimental session directory is not the retail service-5 protocol.

Reaching the connected LSG state is necessary, but it is not proof of profile,
rank, playlist, matchmaking, lobby, or peer/NAT completion.

## Cross-references

- Current project status: `../CURRENT_PROGRESS.md`
- LSG transport: `demonware-lsg.md`
- Overall flow: `demonware-flow.md`
- Storage implementation: `../internal/auth/lsg_storage.go`
- Storage tests: `../internal/auth/lsg_storage_test.go`
- Retail matchmaking: `demonware-matchmaking.md`
