# 2026-07-28 live trace: typed-task reply rejection

## Evidence

The private server log was downloaded from the supplied test link and kept
outside the repository.

- bytes: `74631`
- JSONL events: `243`
- SHA-256:
  `BE56EAE6E4ACEE532297BD135BE374AB1C3A70CC9D904AD2D0084546946706A7`
- authenticated LSG sessions: `2`
- decrypted service requests: `23`

The main session completed authentication and encrypted LSG setup. Client
request IVs advanced monotonically from `0` through `20`; server reply IVs also
advanced monotonically. Requests decrypted successfully and the connection
remained alive, ruling out authentication, key derivation, record encryption,
or immediate transport loss as the playlist blocker.

The main request sequence included storage operation `8` six times and storage
operation `7` once. It never included storage operation `5`. Five server
warnings correctly identified the repeated operation-8/no-operation-5 pattern.

Every operation-8 reply advertised:

- success error `0`;
- operation `8`;
- one result;
- file size `193`;
- file ID `0x1122334455667788`;
- exact filename `playlists.info`;
- playlist SHA-256
  `8586dbd4f1a551da8189d2b6f8c13949bdfb43e6d4d70db110e35efc4199ae86`.

Those semantic fields matched the recovered operation-8 consumer. The failure
was one level earlier in the bitstream.

## Root cause

The emitted operation-8 task payload began:

```text
0a0000000000000000010000000c041400...
```

It started directly with the five-bit typed-`u64` tag and transaction value.
That omitted a required leading bit.

MW2 creates the received lobby `bdBitBuffer` at `0x003d2be8` with type checking
enabled. Constructor path `0x003d2810` immediately consumes the first payload
bit into the buffer's type-checking flag. The low bit of tag `10` is zero, so a
markerless reply produces:

1. `typeChecked = false`;
2. all later typed readers skip their five-bit tags; and
3. the transaction/error/operation fields are decoded one bit out of
   alignment.

The generic reply dispatcher at `0x003ecf18` therefore never reaches the valid
operation-8 result. The playlist completion loop cannot compare
`playlists.info`, cannot copy its file ID, and never starts operation `5`.
Its retry behavior explains the repeated operation-8 requests and the
unchanged **Fetching Playlists** screen.

## Corrected grammar

All bit-packed task replies now begin:

```text
raw bit  type-checking-present = 1
typed u64 transaction ID
typed u32 error code
typed u8  operation ID
operation-specific typed fields
```

Message type `1` remains outside this task payload. For the exact 193-byte
operation-8 response recorded in the trace, prepending the marker changes the
68-byte plaintext payload to:

```text
15000000000000000002000000180828000000000503000028c43bb32aa2199108040000008000000000824001000000000000004038b6b03cb6b439ba39973437b33700
```

The payload remains 68 bytes because the additional significant bit fits in
the existing final-byte padding.

## Confidence and next live assertion

Confidence in this rejection diagnosis is greater than 99%:

- it explains the exact live request loop;
- it follows the client constructor and generic task parser directly;
- it reproduces the one-bit field misalignment;
- the corrected storage and matchmaking serializers pass golden, unit,
  integration, encrypted-flow, and real-auth flow tests.

The first live retest should require no PCAP. Run with sensitive development
logging, enter **Public Playlists**, and check for:

```text
storage operation 8 reply: typeChecked=1
storage operation 5 request: fileID=0x1122334455667788
storage operation 5 reply: typeChecked=1, blobLength=served playlist length
```

Receipt of operation `5` proves MW2 accepted the corrected operation-8
metadata. If operation `5` is received but the screen still stalls, the next
investigation boundary is the operation-5 result and playlist parser. If
operation `5` is still absent, preserve the new sensitive log before changing
any metadata field.
