# BLUS30192 DemonWare Wire Formats and Objects

The PS3 CPU and in-memory game objects are big-endian, but the legacy
DemonWare wire protocol is mixed:

- outer TCP lengths and most lobby numeric fields are little-endian;
- typed `bdBitBuffer` fields are packed least-significant-bit first;
- NP-ticket TLV headers are big-endian;
- IPv4 octets are network order;
- compact `bdAddr` ports are little-endian;
- bandwidth bootstrap/final fields are byte-reversed explicitly by the client.

## Legacy `bdDataType` tags

When `m_typeChecked` is set, every field begins with a five-bit type ID.

| Type | ID | Payload |
| --- | ---: | --- |
| untyped/padding | `0x00` | no standalone payload |
| `BOOL` | `0x01` | 1 bit |
| `UINT8` | `0x03` | 8 bits |
| `UINT16` | `0x06` | 16 bits |
| `SINT32` | `0x07` | 32 bits |
| `UINT32` | `0x08` | 32 bits |
| `SINT64` | `0x09` | 64 bits |
| `UINT64` | `0x0A` | 64 bits |
| `FLOAT64` | `0x0E` | 64 bits |
| `STRING` | `0x10` | NUL-terminated bytes |
| `BLOB` | `0x13` | typed `u32` byte count then raw bytes |

The first bit of an ordinary task/result bit buffer is `m_typeChecked`. The
constructor at MP/SP `0x0004E480` consumes that bit before any field tag is
read.

Operation names and their numeric protocol values are listed on the standalone
[DemonWare Operation Lookup](DemonWare/Operations.md). The remainder of this page uses
those symbolic names.

## PS3 authentication request

```text
TCP record
+0x00  u32 LE    payload length
+0x04  u8        0x00 (plaintext record)
+0x05  u8        0x12 (PS3 auth request)
+0x06  bit       m_typeChecked = 1
       typed u32 request random
       typed u32 title ID
       typed u32 NP-ticket length
       bytes     NP ticket
```

MP `0x000862F0 bdAuthService_buildPS3Request_candidate` constructs this
message. The ticket service ID observed for BLUS30192 is
`UP0002-BLUS30192_00` and the title ID passed into `bdAuthService` is 5087.

`bdAuthService_createPS3AuthCookie` at MP `0x00086788` generates 24 clear
alphanumeric bytes at `bdAuthService+0xC8`. RPCN tickets echo those bytes.
Retail Sony tickets instead contain a distinct opaque 48-byte field; that field
is not the clear cookie.

## Type-19 authentication reply

```text
+0x00  u32 LE    body length
+0x04  u8        0x00 (plaintext record)
+0x05  u8        0x13 (reply type 19)
       bit       m_typeChecked = 0
       u32 LE    status (must be 700)
       u32 LE    auth seed
       152 B     encrypted PS3 client ticket
       128 B     opaque LSG server ticket
       bits      final byte alignment
```

### 152-byte client-ticket plaintext

| Offset | Size | Field |
| ---: | ---: | --- |
| `0x00` | 4 | serialized magic bytes `DE AD BD EF` |
| `0x04` | 1 | platform/reserved |
| `0x05` | 4 | title ID |
| `0x09` | 4 | issue time |
| `0x0D` | 4 | expiry time |
| `0x11` | 8 | license ID |
| `0x19` | 8 | user ID |
| `0x21` | 64 | NUL-padded account-name region |
| `0x61` | 24 | lobby session key |
| `0x79` | 31 | reserved tail |

MP `0x000889D8 bdAuthTicket_deserialize_candidate` reads the 128-byte base
ticket, while MP `0x0008CA28 bdPS3AuthInfo_deserialize` consumes the PS3
extension fields. The following 128-byte server ticket remains separate and is
later carried in the LSG connect body.

### Auth-ticket cipher

```text
iv = Tiger192(auth_seed encoded as four little-endian bytes)[0:8]
ticket_plaintext = 3DES-CBC-DECRYPT(auth_cookie, iv, ticket_ciphertext)
```

The 24-byte auth cookie is the cipher key for this stage. The 24-byte lobby key
inside the decrypted ticket is the key for the next stage.

## Encrypted lobby request

```text
Outer record
+0x00  u32 LE   payload length
+0x04  u8       0x01 (encrypted lobby record)
+0x05  u32 LE   record seed
+0x09  bytes    3DES-CBC ciphertext, multiple of eight

Decrypted request
+0x00  u32 LE   first four HMAC-SHA1 bytes
+0x04  u8       service ID
+0x05  bits     task buffer plus zero padding
```

```text
iv = Tiger192(record_seed encoded little-endian)[0:8]
plaintext = 3DES-CBC-DECRYPT(lobby_key, iv, ciphertext)
expected_mac = HMAC-SHA1(lobby_key, plaintext[5:])[0:4]
```

The MAC excludes the service byte at `plaintext[4]` and covers the entire
padded task buffer beginning at `plaintext[5]`.

Ordinary task buffers begin with:

```text
1 bit       m_typeChecked
typed u8    task ID
typed ...   task-specific fields
```

`LobbyService.BANDWIDTH_TEST` is the exception: its body begins with a raw task
byte and an opaque byte-mode payload.

## Task reply/result envelope

```text
Decrypted reply
+0x00  u32 LE   0xDEADBEEF signature
+0x04  u8       lobby message type 1 (task reply)
+0x05  bit      m_typeChecked = 1
       typed u64 transaction ID
       typed u32 error code
       typed u8  response discriminator
       typed ... count/result objects
       zero      block padding
```

The response discriminator is not always a copy of the request task:

- generic `bdTaskResult` at MP `0x000848C8` / SP `0x000841B8` treats
  discriminators 1 and 5 as one-result forms;
- discriminators 7 and 8 read one typed `u32` result count before invoking
  storage result deserializers;
- the leaderboard completion parser at MP `0x00077580` accepts result
  discriminators 1, 4, and 5 and then reads its own counted page.

Lobby message type 5 is a different byte-mode LSG result. MP
`0x000810C0 bdRemoteTaskManager_handleLsgTaskReply` reads a raw little-endian
transaction ID and stores the remaining bytes at `bdRemoteTask+0x1C`.

## `bdStorage` requests (`LobbyService.STORAGE`)

All rows below are proven independently in MP and SP.

| Operation | Request fields after typed task ID |
| --- | --- |
| `StorageTask.UPLOAD_USER_FILE` | typed `u8` context; typed boolean; typed filename string; typed boolean; BLOB tag; typed `u32` size; raw body |
| `StorageTask.UPDATE_USER_FILE` | typed `u8 0`; typed `u64` existing file ID; BLOB tag; typed `u32` size; raw body |
| `StorageTask.GET_FILE` | typed `u8 0`; typed `u64` publisher or user file ID |
| `StorageTask.LIST_USER_FILES` | typed `u8 0`; typed `u64` owner ID; typed `u32` start; typed `u16` maximum; optional typed filename |
| `StorageTask.LIST_PUBLISHER_FILES` | typed `u8 0`; typed `u32` start; typed `u16` maximum; optional typed filename |

### `bdLobbyFileHeader` result

`bdLobbyFileHeader_deserialize` reads this typed sequence:

```text
u64 file ID
u32 metadata/state 0
u32 metadata/state 1
bool flag 0
bool flag 1
u64 owner ID
string filename (bounded to 128 bytes)
```

The second boolean is required. In memory the header places file ID at `+0x08`,
owner ID at `+0x20`, filename at `+0x28`, and file size at `+0xA8`.

`bdListFilesResult_deserialize` first reads a typed `u32` file size and then
constructs/deserializes the header. `bdLobbyFile_deserialize` instead reads the
header followed by a BLOB tag, typed `u32` count, and raw body bytes.

`StorageTask.UPLOAD_USER_FILE` completion uses `bdQueryResult`, whose result
object contains the returned 64-bit file ID.

## Stats and leaderboard objects (`LobbyService.STATS`)

### `StatsTask.WRITE`

```text
typed u8   context
typed u8   write type
typed s32  board/view ID
typed u64  entity ID (zero means the authenticated local user)
typed s64  rating
typed s32  columns[4 or 10]
```

The write-type low two bits select replace/add/maximum/minimum. Bit 2 makes the
operation conditional on an increased rating.

MP captures use ten columns. A live SP solo-Zombies capture used four columns
for board 1023, so the task number alone does not prove the concrete C++ row
type.

### `StatsTask.WRITE_MULTIPLE`

There is no top-level row count. Rows repeat until alignment padding:

```text
typed u32  board/statistics ID
typed u64  entity ID
typed u8   observed value 1 (enum identity unresolved)
typed u32  field count (observed 5)
typed s64  rating
typed s32  columns[field count - 1]   # four in captures
```

SP `0x00333FC8` serializes four columns from object `+0x64..+0x70`. SP
`0x003360F0` is a distinct ten-column serializer covering `+0x64..+0x88`.

### `StatsTask.READ_BY_ENTITY`

```text
typed u8   context
typed s32  board/view ID
typed u32  entity count
typed u64  entity IDs[count]
```

### `StatsTask.READ_BY_PIVOT_OR_RANK`

```text
typed u8   context
typed s32  board/view ID
typed u64  pivot entity ID
typed u64  top rank
typed s64  maximum results
```

### Leaderboard page result

```text
typed u32  returned row count
typed u32  total available results
repeat returned row count:
    typed u64     entity ID
    typed s64     rating
    typed u64     rank
    typed string  entity name (maximum 64 bytes)
    typed s32     concrete columns[4 or 10]
```

## Matchmaking result object (`LobbyService.MATCHMAKING`)

`bdMatchMakingInfo_deserializeBase` at MP `0x00078408` reads:

```text
BLOB[25]  serialized bdCommonAddr
BLOB[8]   session security ID
BLOB[16]  session security key
s32[4]    base signed attributes
u32[2]    base unsigned attributes
```

WaW's concrete `bdMatchMakingSearchInfo` then reads nine more typed signed
32-bit fields. Extended signed field 6 carries the zero-based playlist ID.

The in-memory accessors expose the security ID at result `+0x04`, security key
at `+0x0C`, and four low-byte attributes at `+0x20..+0x23`.

## KeyArchive values (`LobbyService.KEY_ARCHIVE`)

The observed `bdArchiveValue` signed-32 variant uses discriminator 2.

`KeyArchiveTask.WRITE` values serialize:

```text
value variant
update operation
typed value payload
```

`KeyArchiveTask.READ_BY_KEYS` and `KeyArchiveTask.READ_BY_ENTITY` results
deserialize:

```text
value variant
typed value payload
```

The update-operation byte is deliberately absent from read results. MP
`0x00072758 bdArchiveValue_deserialize` reads the payload immediately after the
variant.

Both read operations return a key-name table and two entity/value-group tables.
Each table begins with a typed `u16` count.

## Performance values (`LobbyService.PERFORMANCE`)

`PerformanceTask.SUBMIT_PERFORMANCE` uses `bdPerformanceInfo` records:

```text
typed u64 user ID
typed s32 performance input
```

`PerformanceTask.GET_PERFORMANCE_VALUES` requests a typed `u32` context followed
by repeated typed `u64` user IDs. Its counted result records are 16 bytes in
memory and deserialize as:

```text
typed u64 user ID
typed s64 performance value
```

## Messaging and lobby push class `0x28`

The outgoing `LobbyService.MESSAGING` /
`MessagingTask.SEND_GLOBAL_INSTANT_MESSAGE` request contains:

```text
typed u8    context
typed BLOB  nested game invite
typed u32   routing mode
typed bool  single-recipient flag
typed u64   recipient IDs (repeated; no count when multi-recipient)
```

The received invite is lobby message type 2, not a task reply:

```text
u32 LE       0xDEADBEEF
u8           lobby message type 2
1 bit        m_typeChecked = 1
typed u32    class discriminator 0x28
typed u64    message ID
typed u64    sender user ID
typed u32    context
typed bool   message flag
typed u64    sender user ID in sender record
typed string sender online ID
typed BLOB   original nested game invite
```

MP/SP `0x0007AEE0 bdLobbyServiceImpl_deserializePushObject_candidate` reads
the class discriminator and invokes the registered factory.

### Nested game invite

```text
"invite\0"
inviter name + "\0"
raw 0x24-byte identity/state block
raw 0x31-byte join block
final flag bit
```

The 49-byte join block is:

| Offset | Size | Field |
| ---: | ---: | --- |
| `+0x00` | 8 | session security ID |
| `+0x08` | 25 | serialized `bdCommonAddr` |
| `+0x21` | 16 | session security key |

## `bdCommonAddr` and NAT traversal

The compact common address is:

| Offset | Size | Field |
| ---: | ---: | --- |
| `+0x00` | 6 | local `bdAddr` 0 |
| `+0x06` | 6 | local `bdAddr` 1 |
| `+0x0C` | 6 | local `bdAddr` 2 |
| `+0x12` | 6 | public/external `bdAddr` |
| `+0x18` | 1 | NAT type |

Each `bdAddr` is four network-order IPv4 octets followed by a little-endian
`u16` port.

The 29-byte NAT traversal packet is:

| Offset | Size | Field |
| ---: | ---: | --- |
| `0x00` | 1 | packet type |
| `0x01` | 2 | protocol version |
| `0x03` | 10 | truncated authentication tag |
| `0x0D` | 4 | traversal identifier |
| `0x11` | 6 | requester `bdAddr` |
| `0x17` | 6 | target `bdAddr` |

The authentication tag covers the final 16 bytes. Direct probe type `0x0D` is
accepted only when its identifier matches the receiver's common-address
identifier.

## Bandwidth byte mode (`LobbyService.BANDWIDTH_TEST`)

`BandwidthTask.RUN_TEST` bypasses typed task fields. MP `0x00075B50` sends a
raw 16-byte bootstrap request. The bootstrap result parser at `0x00075318`
reads:

```text
u8       status
u32[7]   packet/timing configuration (explicitly byte-reversed)
u16      UDP port
IPv4     four network-order octets
u8[8]    validation token
```

Upload packets begin with a four-byte big-endian sequence and the eight-byte
token, followed by padding to the configured packet size. The client sends the
configured sequence range across the configured upload-duration window, then
enters the download phase.

Final report data consists of five raw `u32` measurements. MP
`0x000771A0 bdBandwidthTestResult_deserialize` byte-reverses each value.
