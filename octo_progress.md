# MW2 PS3 playlist protocol recovery

## Purpose

This document describes the exact protocol used by the PlayStation 3 version
of _Call of Duty: Modern Warfare 2_ to obtain `playlists.info` from
Demonware. It records what was recovered, how it was verified, and how a
replacement server should implement the exchange.

The playlist blocker is solved at the packet-schema and file-format levels.
The remaining external check is to run the implementation against a new live
PS3/RPCS3 session and confirm that the game accepts both generated replies.

## Short answer

The game performs two `bdStorage` tasks:

1. service `10`, operation `8`: list publisher files;
2. find the record whose filename is `playlists.info`;
3. service `10`, operation `5`: request that file by its 64-bit file ID;
4. read a blob from the operation-5 reply;
5. parse the blob as a line-oriented text file.

`playlists.info` is not JSON and is not a second Demonware binary format.

## Sources and validation

The result was derived from:

- `default_mp.elf`, imported into Ghidra as
  `PowerPC:BE:64:64-32addr`;
- the MW2 storage serializers and reply parsers;
- the MW2 text playlist parser;
- the supplied PS3 packet capture;
- a previously captured decrypted operation-8 request;
- the preserved Ghost Demonware implementation as a transport cross-check;
- deterministic codec, crypto, and full-flow tests.

Relevant MW2 addresses:

|      Address | Recovered purpose                       |
| -----------: | --------------------------------------- |
| `0x003e6f60` | generic lobby-task request builder      |
| `0x003eda48` | service 10 / operation 8 serializer     |
| `0x003edf18` | service 10 / operation 5 serializer     |
| `0x003e6c08` | remote-task reply dispatch              |
| `0x003eca78` | operation-8 result parser               |
| `0x003ec558` | operation-5 result/blob parser          |
| `0x003ecf18` | storage task-reply envelope parser      |
| `0x00258bf0` | `playlists.info` text parser            |
| `0x0074ac00` | playlist keyword table                  |
| `0x003f81d0` | encrypted client-to-server send path    |
| `0x003f8b50` | encrypted server-to-client receive path |
| `0x0049e8b0` | Tiger-based IV generation               |

The supplied capture is:

```text
captures/mw2 ps3.pcapng
size:   730248 bytes
SHA256: 33A3EC8EB0A984DB45FBF5BE491541C7B974B4A6E24EC95A81ACE863D3FAD329
```

The capture validates the auth/lobby TCP record boundaries, encrypted-frame
sizes, seeds, and block alignment. Its retail lobby payload cannot be
decrypted from the PCAP alone because the client-generated session secret is
not present in plaintext.

## Bit-buffer encoding

MW2 uses an LSB-first bit buffer:

- the least-significant bit of a value is written first;
- five-bit type tags are also LSB-first;
- fields are not aligned to byte boundaries;
- values begin immediately after their five-bit tags.

Recovered tags:

|  Tag | Payload                     |
| ---: | --------------------------- |
|  `0` | request argument terminator |
|  `1` | one-bit boolean             |
|  `3` | `u8`                        |
|  `6` | `u16`                       |
|  `8` | `u32`                       |
| `10` | `u64`                       |
| `16` | NUL-terminated string       |
| `19` | blob                        |

A blob is encoded as tag `19`, followed by a typed `u32` length, followed by
that many raw bytes.

## Operation 8: list publisher files

### Client request

The complete decrypted request shape is:

```text
raw u8 service                    = 10
raw bit type-checking-present     = 1
typed u8 operation                = 8
typed u8 value                    = 0
typed u32 value                   = 0
typed u16 maximum results         = 100
[optional typed string filter]
raw 5-bit terminator              = 0
zero bits to the end of the byte
```

With no filename filter, the exact bytes are:

```text
0a07c2004000000000860c0000
```

This value was produced independently by the recovered serializer and matches
the previously captured decrypted client request byte-for-byte.

The first byte, `0x0a`, is the storage service ID. It is not a generic lobby
message type.

### Server reply

A successful operation-8 reply is:

```text
raw u8 message type               = 1
typed u64 transaction ID
typed u32 error code              = 0
typed u8 operation                = 8
typed u32 result count
file[result count]
```

Each file record is read in this exact order:

```text
typed u64 file ID
typed u32 value 1
typed u32 value 2
typed bool flag 1
typed bool flag 2
typed u64 value 3
typed string filename
```

Only `file ID` and `filename` are required by the recovered MW2 playlist call
chain. The other five fields should be set to zero unless their semantics are
needed for another storage feature.

For the playlist response:

```text
file ID  = a stable, nonzero u64 chosen by the server
filename = "playlists.info"
```

The server must remember the chosen file ID so that operation 5 can resolve
it. It does not need to be a real filesystem inode or database ID.

## Operation 5: get publisher file

### Client request

```text
raw u8 service                    = 10
raw bit type-checking-present     = 1
typed u8 operation                = 5
typed u64 file ID
raw 5-bit terminator              = 0
zero bits to the end of the byte
```

The file ID is the value returned in the selected operation-8 record.

### Server reply

Operation 5 does **not** have a result-count field:

```text
raw u8 message type               = 1
typed u64 transaction ID
typed u32 error code              = 0
typed u8 operation                = 5
the same seven-field file record
typed blob:
    typed u32 byte length
    raw file bytes
```

The record should contain the same file ID and filename returned by operation 8. The blob contains the complete `playlists.info` text.

MW2 allocates a `0x20000`-byte buffer for this blob. Reject or shorten files
larger than `131072` bytes.

## Transaction IDs

The reply envelope contains a typed `u64` transaction ID, although the
operation request payload itself does not contain one.

MW2's task manager dispatches replies against its pending-task queue. A server
should use a monotonically increasing reply transaction ID for compatibility,
starting at zero for the first task on a connection. The provided codec accepts
the ID as an explicit argument.

## Lobby encryption and framing

### Common outer frame

Encrypted lobby records use:

```text
u32le length_after_this_field
u8    encrypted = 1
u32le IV seed
bytes 3DES-CBC ciphertext
```

The declared length is:

```text
1 + 4 + ciphertext_length
```

The ciphertext length must be a positive multiple of eight.

The 24-byte lobby session key is used as a 3DES-EDE key. The CBC IV is:

```text
Tiger(u32le(seed))[0:8]
```

### Client-to-server plaintext

MW2 sends:

```text
bytes HMAC-SHA1(logical_plaintext[1:] + padding, session_key)[0:4]
bytes logical_plaintext
bytes padding
```

Important details:

- `logical_plaintext[0]` is excluded from the HMAC;
- for playlist requests that first byte is service ID `10`;
- the HMAC covers the padding;
- every padding byte equals `seed & 0xff`;
- the whole body is padded to an eight-byte boundary before 3DES-CBC.

These rules are directional. They describe records sent by MW2 to the server.

### Server-to-client plaintext

The preserved server convention is:

```text
u32le 0xDEADBEEF
bytes logical reply
zero padding to an 8-byte boundary
```

The logical reply starts with message type `1`.

MW2's receive path decrypts and discards the four-byte prefix. It does not
calculate a server-reply HMAC or compare the prefix against `DEADBEEF`.
`DEADBEEF` should still be used because it is the established server
convention and provides a useful diagnostic when validating a session key.

Do not use the client HMAC format for server replies.

## `playlists.info` text format

The operation-5 blob is UTF-8/ASCII text. The core structure is:

```text
version NUMBER

rule COMMAND_TEXT
set COMMAND_TEXT

gametype IDENTIFIER
name LANGUAGE "TEXT"
script SCRIPT
teambased
hardcore
rule COMMAND_TEXT
set COMMAND_TEXT

playlist ID
name LANGUAGE "TEXT"
description LANGUAGE "TEXT"
lootgroup NAME
ranked
nojip
nolooping
partyteams
unlockxp NUMBER
maxparty NUMBER
minparty NUMBER
numrounds NUMBER
dlc NUMBER
rule COMMAND_TEXT
set COMMAND_TEXT
MAP,GAMETYPE,WEIGHT
```

Commands apply to the most recently opened gametype or playlist block.
Blank lines are optional. `//` comments are accepted.

Example:

```text
version 504

gametype dm
name english "Free-for-All"
script dm

playlist 0
name english "Free-for-All"
description english "Every man for himself."
ranked
maxparty 1
minparty 1
mp_afghan,dm,100
```

Recovered limits:

| Item                  |                   Limit |
| --------------------- | ----------------------: |
| complete blob         |         `0x20000` bytes |
| gametypes             |                      32 |
| playlist ID           |            0 through 23 |
| entries per playlist  |                     210 |
| entry weight          | positive signed integer |
| map identifier        |                15 bytes |
| gametype identifier   |                15 bytes |
| script identifier     |                15 bytes |
| rule buffer per scope |           `0x800` bytes |
| storage filename      |      127 bytes plus NUL |
| party size            |            1 through 18 |

Every gametype used by an entry must already be declared. Each gametype needs
a script and an English name. Each playlist needs an English name and at
least one entry.

The literal parser keywords are `nolooping` and `dlc`. Do not use the related
error-text spellings `noloop` or `requiredDlcPack`.

## Recommended server implementation

### 1. Route storage service 10

After decrypting and authenticating a client lobby record, inspect the first
logical byte. Route value `10` to the storage handler.

Decode the type-checking marker and typed operation field. For the playlist
bootstrap, handle operations `8` and `5`.

### 2. Handle operation 8

Create one file record:

```python
FileInfo(
    file_id=0x1122334455667788,
    value_u32_1=0,
    value_u32_2=0,
    flag_1=False,
    flag_2=False,
    value_u64=0,
    filename="playlists.info",
)
```

Encode it with `encode_list_reply()`, wrap the returned logical plaintext with
`frame_server_message()`, and send the complete frame.

### 3. Handle operation 5

Decode the requested `u64` file ID. Reject unknown IDs or map the chosen
playlist ID to the configured text file.

Read and validate the text file before sending it. Encode the result with
`encode_get_reply()`, then wrap it with `frame_server_message()`.

### 4. Keep framing and application encoding separate

The playlist codec produces complete logical plaintext, including its first
service/message byte. The transport codec encrypts that complete value.

Correct:

```python
logical = encode_list_reply(transaction_id=1, files=[info])
wire = frame_server_message(
    logical_plaintext=logical,
    key=session_key,
    seed=next_seed,
)
socket.sendall(wire)
```

Do not prepend another message-type byte. `encode_list_reply()` already starts
with message type `1`.

### 5. Send complete TCP records

TCP may split or combine records. On receive:

1. accumulate at least four bytes;
2. read the little-endian length;
3. accumulate exactly `4 + length` bytes;
4. process that record;
5. retain any following bytes for the next record.

Do not assume one TCP `recv()` call equals one Demonware record.

## Included implementation

The workspace contains:

- `tools/mw2_playlist_codec.py`  
  Strict LSB-first request/reply codec for operations 8 and 5.

- `tools/mw2_lobby_transport.py`  
  Direction-aware lobby framing, Tiger IV generation, 3DES-CBC, client HMAC,
  client padding, and server `DEADBEEF` framing.

- `tools/validate_full_playlist_flow.py`  
  Deterministic encrypted operation-8 request/reply followed by operation-5
  request/reply and text parsing.

- `tools/validate_playlists_info.py`  
  Validator for the recovered playlist grammar and limits.

- `tools/analyze_mw2_pcap.py`  
  TCP reassembly and structural PCAP validation, with optional session-key
  decryption.

- `examples/playlists.info`  
  A conservative example accepted by the local validator.

## Validation commands

From `C:\Users\ardia\Documents\ReverseMW2`:

```powershell
cargo build --manifest-path .\tools\tiger_iv\Cargo.toml
python .\tools\mw2_playlist_codec.py
python .\tools\mw2_lobby_transport.py --self-test
python .\tools\validate_full_playlist_flow.py
python .\tools\validate_playlists_info.py .\examples\playlists.info
python .\tools\analyze_mw2_pcap.py ".\captures\mw2 ps3.pcapng"
```

Expected important results:

```text
PASS: observed op8 request and MW2 op8/op5 reply shapes
PASS: Tiger IV and 3DES-CBC match the independent reference vector
PASS: client HMAC/counter padding and tamper rejection
PASS: server DEADBEEF signature convention and zero padding
PASS: encrypted service-10/op8 request -> list reply
PASS: selected file ID -> encrypted service-10/op5 request/reply
PASS: downloaded playlists.info parsed
```

## PCAP observations

The capture contains two relevant TCP/3074 flows:

```text
auth:
192.168.0.199:61641 <-> 185.34.107.28:3074

lobby:
192.168.0.199:61639 <-> 185.34.107.69:3074
```

The lobby client begins with a special 152-byte login/ticket record. Normal
length-prefixed encrypted records follow it.

The capture has a 66-byte gap in the client lobby stream corresponding to two
missing 33-byte records. This does not affect the server stream or the
structural validation of the captured records.

The largest captured server lobby record has:

```text
declared length: 63373
ciphertext:      63368 bytes
```

Its length and 3DES block alignment are valid. The passive capture cannot
prove its decrypted contents without the retail session key.

## Troubleshooting

### The client repeats the operation-8 request

Likely causes:

- reply begins with service ID `10` instead of message type `1`;
- operation-8 count is missing or encoded with the wrong tag;
- a file record field is missing or out of order;
- reply was wrapped using the client HMAC format;
- TCP length excludes or includes the wrong bytes;
- the server sent a second message-type byte;
- the session key or IV seed is wrong.

### The client never sends operation 5

Check that:

- operation-8 error code is zero;
- result count is at least one;
- the first file record begins immediately after that count with a typed `u64`;
- filename is exactly `playlists.info`;
- filename is a typed, NUL-terminated string;
- file ID is nonzero and encoded as typed `u64`;
- the reply operation is typed `u8` value `8`.

### Operation 5 arrives but parsing fails

Check that:

- the reply does not contain an operation-8-style result count;
- the same seven file fields are present;
- the blob starts with tag `19`;
- the nested length is a typed `u32`;
- the stated length exactly matches the following raw bytes;
- the blob is no larger than `0x20000`.

### The playlist downloads but the menu still stalls

Run the text validator and check:

- `version` is present and nonnegative;
- at least one gametype and playlist exist;
- every gametype has `script` and `name english`;
- every playlist has `name english` and at least one entry;
- entry gametype names match declared identifiers;
- playlist IDs are between 0 and 23;
- party sizes are between 1 and 18;
- entries use commas: `map,gametype,weight`.

## What is proven and what remains

Proven:

- service and operation IDs;
- exact operation-8 request bytes;
- operation-8 argument order;
- operation-5 file-ID request;
- reply envelope fields;
- exact seven-field file record;
- operation-5's lack of a result count;
- blob encoding;
- LSB-first typed bit format;
- text grammar and hard limits;
- outer TCP framing;
- directional encryption-prefix, padding, IV, and HMAC rules;
- deterministic encrypted operation-8 to operation-5 flow.

Still to verify externally:

- one newly generated operation-8 reply accepted by the actual game;
- the subsequent operation-5 request observed live;
- one newly generated operation-5 reply accepted;
- the UI leaving “Fetching Playlists.”

That final check requires a live session because the replacement server knows
the active 24-byte session key. The retail PCAP alone cannot supply that key.
