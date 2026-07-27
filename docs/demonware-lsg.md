# LSG lobby service (TCP 3074, stream 11)

Long-lived connection carrying the actual lobby bootstrap. Starts with an
unencrypted hello handshake, then every record is 3DES-CBC encrypted with a
SHA-1 HMAC. Implemented in `internal/auth/raw_server.go` (`handleLSG`),
`internal/auth/lsg_protocol.go`, and `internal/auth/lsg_record.go`.

## Record framing

Same outer length prefix as auth:

```
uint32  body_length   (little-endian, bytes after this field)
byte    envelope_flag
...     body
```

- `flag == 0xff` — the initial hello record (special, see below).
- `flag == 0x00` — unencrypted control record (only the hello-ack uses this).
- `flag == 0x01` — encrypted record.

### Encrypted record layout (`flag == 0x01`)

```
uint32  body_length
byte    0x01
uint32  iv_seed
bytes   ciphertext (multiple of 8)
```

- IV = `Tiger(iv_seed_le)[:8]`.
- Cipher = 3DES-CBC with the 24-byte session key from auth.
- Plaintext = `uint32 hmac_le || byte message_type || payload`, padded to an
  8-byte boundary.
- HMAC = first 4 bytes (LE) of `HMAC-SHA1(session_key, message_type||payload)`.

Client request `iv_seed` values are a simple incrementing counter
(observed `0x00000004`, then `0x00000008`); server responses use random seeds.

## Observed record sequence (from the capture)

Direction is relative to the game client. Encrypted bodies cannot be decrypted
from the pcap (see `demonware-auth.md`), so contents are inferred from the ELF
and the server implementation.

| # | Dir | Bytes | Record | Meaning |
|--:|-----|------:|--------|---------|
| 0 | C→S | 184 | hello `flag=0xff`, type 7 | LSG connect: game id + LSG ticket |
| 2 | S→C | 15  | unencrypted `flag=0x00` | hello-ack: 5 bits + 8-byte connection nonce |
| 3 | S→C | 65  | encrypted | first server task/notification |
| 4 | S→C | 449 | encrypted | lobby service data |
| 5 | S→C | 449 | encrypted | lobby service data |
| 6 | S→C | 41  | encrypted | small result |
| 7 | C→S | 41  | encrypted (iv_seed=4) | client task request |
| 8 | S→C | 49  | encrypted | task reply |
| 9 | S→C | 161 | encrypted | task reply |
| 10 | S→C | 63377 | encrypted | **bulk storage payload (~63 kB)** — playlists / MOTD / config |
| 12 | S→C | 41 | encrypted | result |
| 13 | C→S | 41 | encrypted (iv_seed=8) | client task request |
| 14 | S→C | 41 | encrypted | result |

The ~63 kB record at step 10 is the largest single object and is almost
certainly the storage/publisher file bundle that seeds playlists and
message-of-the-day (`bdStorage` / `bdGetFileResult` in the ELF).

## Hello handshake

### Client hello (`flag == 0xff`, type 7)

Uses a length quirk: the outer `body_length` is the true body length **+ 28**.
The server special-cases this (`parseLSGInitialRecord` accepts both
`len-4` and `len+28`). Body:

```
uint32  body_length (+28 quirk)
byte    0xff
uint16  0xffff
uint32  inner_length
uint16  0x0000
byte    0x07                 initial type
--- bit-packed ---
1 bit   initial flag = 1
typed   game_id  (u32)   0 sentinel (RPCN/PS3) or 0x14a0 accepted
typed   random_number (u32)
bytes   ticket[128]          the LSG ticket from the auth response
```

The server looks the ticket up (`lsgSessionStore.consume`, keyed on the first
24 bytes) to recover the session key, then builds the connection.

### Server hello-ack (`flag == 0x00`, unencrypted)

`helloResponse()` writes 5 bits (value 4) then an 8-byte little-endian
connection nonce. Captured: `0b000000 00 0415989b836e3dfbe515` → 11-byte body.

## Post-hello messages

After the hello-ack, the client sends its first **encrypted** record. In the
current server (`handleLSGMessage`):

- **type `0x12` (lobby connection-ID notification)** — payload is a bd-typed
  u64. Server records `connectionID`, sets `loggedIn`, sends no reply.
- **type `0x01` (task result / RPC)** — dispatched by service+operation id via
  `handleTask`.

### bd task encoding

Task payloads use bd type-tagged values (`writeU8`/`writeU16`/`writeU32`/
`writeU64`/`writeF32`/`writeString`). A task reply (`taskReply`) is:

```
u64  transaction id = 0
u32  error_code
u8   operation_id
u32  result_count
u32  result_count      (repeated)
...  results
```

### Currently handled services (`handleTask`)

| Service | ID | Op | Behaviour |
|---------|---:|---:|-----------|
| Title Utilities | 12 | 6 | returns current unix time |
| DML (geo) | 27 | 2 | returns `US` / `United States` + zero coords |
| DML (geo) | 27 | 3 | as above + extra zero fields |
| Bandwidth | 18 | 1 | returns "service not available" |
| Storage | 10 | * | returns `bdErrorNoFile` (1000) |
| default | — | — | returns `bdErrorServiceNotAvailable` (108) |

These are stubs. The real retail server returns actual storage files (the
63 kB bundle), which is the main gap for full lobby entry.
