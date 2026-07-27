# Authentication service (TCP 3074, stream 9)

Stateless request/response. One 320-byte request in, one 295-byte success record
out, then the connection closes. Implemented in `internal/auth/raw_server.go`
(`handle`) and `internal/auth/legacy_response.go`.

## Framing

All Demonware records on 3074 share the same outer framing:

```
uint32  body_length   (little-endian, counts every byte after this field)
byte    envelope_type
...     body
```

For the auth request/response the envelope byte is `0x00`. Payload fields inside
the body are encoded with an **LSB-first bit reader/writer** (see
`lsbBitReader` / `lsbBitWriter`): a 1-bit flag, then "typed" values where a
5-bit type tag `8` precedes a 32-bit little-endian integer.

## Request (client → server, 320 bytes)

Captured head: `3c010000 00 121170f7 b92002a5 0000402c ...`

```
uint32  body_length = 0x0000013c (316)
byte    0x00                      envelope type
--- bit-packed body (offset 6) ---
1 bit   initial flag = 1
typed   random_number  (u32)
typed   game_id        (u32) = 0x000014a0   (MW2)
typed   ticket_length  (u32)
bytes   authorization_ticket[ticket_length]
```

The authorization ticket embeds platform/PSN identity. Two fields are extracted
from it by the server:

- **Platform key** — `ticket[32:56]` (24 bytes). Used as the 3DES key that
  encrypts the game ticket in the response.
- **LSG session key** — 24 bytes read from inside the ticket at a
  platform-dependent offset:
  - `151` for a retail PS3/NP ticket.
  - `91` when the ticket contains the ASCII marker `RPCN` (RPCN clients).
  This key is what the following LSG connection will use for 3DES.

Visible strings in a real request: user id (e.g. `179712`), `Tustin`,
`UP0002-BLUS30377_00` (title/region), an NP ticket token, and `RPCN` for RPCN
clients.

## Response (server → client, 295 bytes)

Captured head: `23010000 00 13 78050000 50844fcb ...`

```
uint32  body_length = 0x00000123 (291)
byte    0x00        envelope type
byte    0x13        legacy reply type
--- bit-packed body (offset 6) ---
1 bit   error flag = 0
u32     status = 700           (bdAuthNoError)
u32     iv_seed                (random; seeds the game-ticket IV)
bytes   encrypted_game_ticket[128]
bytes   client_session_key[24]
bytes   lsg_ticket[128]        (a.k.a. platform proof slot)
```

### Game ticket (128 bytes, encrypted)

Built in `buildLegacyGameTicket`, then 3DES-CBC encrypted with the platform key
and IV = `Tiger(iv_seed)[:8]`:

```
0x00  u32   magic = 0xefbdadde
0x04  u8    type  = 0
0x05  u32   game_id
0x09  16×   0x0a filler
0x19  u64   user_id = 0x01100001deadc0de
0x21  0x40  username ("Tustin"), null/zero padded
0x61  24×   session_key
0x79  ..    0x0a filler to 128
```

The client decrypts this with its own copy of the platform key to recover the
session key. **Important consequence for reverse engineering:** because the
platform key lives only inside the PSN/RPCN ticket (not on the wire in a
reusable form), the captured retail session key cannot be recovered from the
pcap. The skipped test `TestDeriveCapturedLSGSessionKey` documents this dead
end. The encrypted LSG payloads in stream 11 therefore cannot be decrypted from
the capture alone — the capture is a **framing/flow** reference, not a
plaintext oracle.

### LSG ticket (128 bytes)

`buildCandidateLSGTicket`: `session_key[24]` + 8 zero bytes + 4 zero bytes +
`"Tustin"`. This is the token the client echoes back in the LSG hello so the
server can look the session up (see `demonware-lsg.md`). The server stores the
mapping `lsg_ticket → session_key` keyed on the first 24 bytes.
