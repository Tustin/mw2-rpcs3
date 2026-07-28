# Current status of MW2 Demonware server emulation

_Last updated: 2026-07-27 after the 20:44–20:45 RPCS3 run._

## Executive summary

The project now gets MW2 on RPCS3 through dynamic Demonware authentication, the encrypted Lobby Service Gateway (LSG) handshake, and a sustained post-login service-task session. The game displays **“Connecting to Matchmaking Server Complete.”** and continues sending storage, bandwidth, and stats requests without crashing or reconnecting.

The most recent fix corrected the successful storage task-result header. MW2 expects both `numResults` and `totalNumResults` before the first storage result. With both counts present, RPCS3 accepted repeated publisher-file list replies and advanced into stats traffic. The earlier storage deserialization crash is therefore fixed.

The client has not yet sent storage operation `5` (`getFile`) for `playlists.info`. The current blocker is no longer authentication, encryption, or basic `bdFileInfo` deserialization; it is determining why the client lists the publisher file successfully but does not select/download it.

## Current end-to-end state

| Phase | Status | Evidence / notes |
|---|---|---|
| Listener startup | Working | Auth, LSG/lobby, NAT, and HTTP listeners start. |
| Auth request parsing | Working | Retail/RPCN NP-ticket requests are recognized and decoded. |
| Dynamic auth response | Working | A fresh 24-byte session key, game ticket, and LSG ticket are generated per connection; the captured retail response is not replayed. |
| RPCN key extraction | Working | The LSG key is located relative to the `RPCN` marker (`marker offset - 60`), avoiding a brittle absolute offset. |
| LSG hello | Working | The client echoes the issued ticket, the server consumes the ticket→key mapping, accepts RPCN’s zero game-ID sentinel where applicable, and returns the hello acknowledgement. |
| Encrypted LSG records | Working | Client requests decrypt and validate; server replies encrypt with 3DES-CBC and the expected record framing. |
| Connection-ID notification | Working | Outer message type `0x12` is treated as the lobby connection-ID notification and does not receive an incorrect task reply. |
| Service task dispatch | Working | Service and operation IDs are parsed from the client’s bit-packed request format. |
| Title utilities / DML | Minimally implemented | Time and geographic stubs exist. |
| Bandwidth service | Minimally implemented | Operation `1` receives the service-task reply shape expected by the client. |
| Storage list operation `8` | Accepted by RPCS3 | Returns one `playlists.info` metadata result with both result counts. No deserialization crash in the latest run. |
| Storage owner-list operation `7` | Accepted by RPCS3 | Returns a successful empty result (`0, 0`). |
| Storage get operation `5` | Implemented server-side, not observed client-side | Can return metadata plus the raw playlist blob when requested with the advertised file ID. RPCS3 has not requested it yet. |
| Stats operation `7` | Minimally implemented | Returns an empty success; the latest run reached repeated stats requests after storage. |
| Playlist parsing / lobby population | Not reached | No operation `5` download yet, so the game has not consumed the local playlist. |
| Profile, rank, create-a-class, matchmaking/lobby population | Not implemented | These are later bootstrap stages after playlist selection/download. |

## Protocol findings established so far

### Authentication

- Auth and LSG are separate TCP connections on port `3074`.
- The auth request contains the MW2 game ID (`0x14a0`) and an NP/RPCN authorization ticket.
- The response is generated dynamically and contains an encrypted game ticket, client/session data, and an LSG ticket.
- The server stores a one-use mapping from the issued LSG ticket to the 24-byte 3DES session key.
- Retail and RPCN ticket layouts differ. Runtime RPCN tickets showed that the useful key position is stable relative to the `RPCN` marker rather than to the beginning of the whole variable-length ticket.
- The retail packet capture remains useful for framing and flow, but its encrypted LSG payload cannot be decrypted without the original platform key.

### LSG transport

- The persistent lobby channel is `bdLobbyConnection` over TCP, not the UDP/SCTP-like `bdConnection` transport.
- Encrypted records use:
  - a little-endian length prefix;
  - envelope flag `0x01`;
  - a 32-bit IV seed;
  - IV derived from the seed with Tiger;
  - 3DES-CBC using the auth-issued 24-byte key;
  - plaintext shaped as `u32 HMAC/prefix + u8 messageType + payload + zero padding`.
- Client request HMAC validation now succeeds with the dynamically derived RPCN key.
- Server responses currently use the `0xdeadbeef` prefix accepted by this client path; local round-trip diagnostics intentionally report that this is not a computed request HMAC while still confirming the message type and payload.
- The server maintains one monotonically increasing task transaction sequence across normal and storage replies.

### Task/result encoding

There are two relevant serializers:

- Normal service replies use byte-aligned typed fields (`bdByteWriter`).
- MW2 storage requests and replies use the LSB-first bit-packed typed serializer (`bdBitReader` / `bdBitWriter`).

A successful task result includes:

1. transaction ID (`u64`),
2. error code (`u32`),
3. operation ID (`u8`),
4. `numResults` (`u32`),
5. `totalNumResults` (`u32`),
6. zero or more result objects.

The latest runtime test resolves the earlier ambiguity about the storage counts: **MW2 requires both count fields for these successful storage replies.** A one-count operation-8 response was 64 bytes and led to the client-side deserialization failure/retry behavior. The corrected two-count response is 68 bytes and is accepted.

### Storage metadata and playlist serving

The advertised publisher file currently uses:

- file ID: `0x1122334455667788`;
- filename: `playlists.info`;
- public visibility;
- zero owner and timestamps;
- the MW2 `bdFileInfo` typed-field order confirmed through ELF/PDB analysis.

Implemented storage operations:

| Operation | Meaning | Current response |
|---:|---|---|
| `7` | List files by owner | Successful empty result. |
| `8` | List publisher/all files | One `bdFileInfo` result for `playlists.info`. |
| `5` | Get file | If the requested file ID matches, returns one result containing `bdFileInfo` and the raw playlist blob. |

`playlists.info` is loaded from `MW2_PLAYLISTS_FILE`, then the repository root fallback, with an additional test-friendly relative fallback. Empty files and files larger than `0x20000` are rejected. The current fixture is a minimal version-504 Free-for-All playlist.

## Latest RPCS3 run: 2026-07-27 20:44–20:45

### Successful sequence

1. RPCS3 authenticated dynamically and received a fresh session key and LSG ticket.
2. It connected to LSG and completed the hello exchange.
3. Client encrypted service requests decrypted successfully.
4. The client issued storage operation `8` several times.
5. Each operation-8 reply contained one result and both count fields, producing a 68-byte plaintext payload / 89-byte encrypted frame.
6. The client issued storage owner-list operation `7` and accepted the successful empty result.
7. The same LSG connection stayed alive and advanced into service `4`, operation `7` stats traffic, reaching at least step 25.

Observed storage transactions:

| LSG step | Service | Operation | Transaction | Result counts |
|---:|---:|---:|---:|---|
| 3 | `10` | `8` | 0 | `1, 1` |
| 4 | `10` | `8` | 1 | `1, 1` |
| 5 | `10` | `7` | 2 | `0, 0` |
| 7 | `10` | `8` | 3 | `1, 1` |
| 10 | `10` | `8` | 4 | `1, 1` |

### Interpretation

- The prior RPCS3 crash while processing storage metadata is fixed.
- The corrected replies are not causing an auth restart, LSG disconnect, or immediate malformed-result loop.
- Repeated operation-8 requests appear to be distinct queued initialization requests: their request suffixes/sequence values advance, and successful requests to other services are interleaved.
- No storage operation `5` appears in the run, so `playlists.info` was advertised but not downloaded.
- Reaching stats traffic proves the bootstrap progressed beyond the original storage failure, but it does not yet prove that playlists, rank, profile, or lobby data loaded.

## Important corrections to earlier notes

- Earlier progress text said operation `8` should contain only one serialized result count. The latest implementation plus live RPCS3 behavior disproves that conclusion for this task-result path. Both `numResults` and `totalNumResults` are required.
- “Connecting to Matchmaking Server Complete.” means the client reached the connected LSG state. It does **not** mean the full online bootstrap, playlist fetch, profile/rank initialization, or lobby population is complete.
- The current issue is no longer the old RPCN HMAC/key-offset failure. Runtime requests now decrypt correctly using the marker-relative key extraction.

## Current implementation areas

- `internal/auth/raw_server.go`
  - Auth/LSG connection handling, RPCN key diagnostics, request logging, encrypted response dispatch.
- `internal/auth/legacy_response.go`
  - Dynamic MW2 authentication response and ticket generation.
- `internal/auth/lsg_record.go`
  - LSG record parsing, encryption/decryption, 3DES, IV derivation, and HMAC validation.
- `internal/auth/lsg_protocol.go`
  - LSG session state, normal typed task replies, service dispatch, title utilities, DML, bandwidth, and stats stubs.
- `internal/auth/lsg_storage.go`
  - MW2 bit-packed storage request parser, reply serializer, transaction IDs, operations `5`/`7`/`8`, `bdFileInfo`, and playlist loading.
- `internal/auth/lsg_storage_test.go`
  - Storage request/reply layout, count fields, transactions, metadata, blob serving, size limits, and encryption-prefix regression tests.

## Verification

After the storage result-header correction:

- `gofmt` completed successfully.
- `go test ./internal/auth` passed.
- `go test ./...` passed for the full repository.
- No linter errors were reported for the edited storage files.
- Live RPCS3 accepted the corrected storage replies and continued into stats requests.

## Current blocker

The next single problem to solve is:

> Why does MW2 accept/list `playlists.info` through storage operation `8` but never issue operation `5` to retrieve the advertised file?

Likely investigation points, in priority order:

1. Trace the MW2 publisher-file list callback/result-selection path in `default_mp.elf`, from the accepted `bdFileInfo` result to the decision to call `getFile`/`getPublisherFile`.
2. Verify every advertised metadata field used by that decision, especially file ID, filename, visibility flags, timestamps, owner ID, and whether MW2 expects file size or another field not present in the current seven-field serialization.
3. Determine whether operation `8` is actually the expected publisher-list task for playlist discovery or whether its arguments select a different namespace/category.
4. Correlate each repeated operation-8 request’s decoded arguments with its game initialization purpose rather than treating the trailing request bytes as opaque.
5. Check the RPCS3 log and relevant client error strings immediately after each accepted list result for a silent filename/version/filter rejection.

Do not move on to profile/rank implementation until the operation-8 → operation-5 transition is understood or ruled out; playlist retrieval is the current flow-order blocker.

## Later work, after playlist retrieval

1. Confirm operation `5` returns the raw local `playlists.info` bytes and that MW2 parses version 504.
2. Add/serve MOTD or any other required publisher files discovered by the client.
3. Implement the profile/rank/stat result structures required after the existing empty stats stub.
4. Implement create-a-class and related per-user storage/profile tasks.
5. Continue into matchmaking/lobby population and NAT/session behavior.
6. Replace temporary diagnostics/stubs with production-safe validation once wire compatibility is established.

## Reference material

- Retail source of truth: `captures/mw2 ps3.pcapng`
- Client executable: `captures/default_mp.elf` (loaded in IDA)
- Cross-reference symbols: `iw6_ds_ps3.exe` / `iw6_ds_ps3.pdb`
- Playlist fixture: `playlists.info`
- Focused docs:
  - `docs/demonware-flow.md`
  - `docs/demonware-auth.md`
  - `docs/demonware-lsg.md`
  - `docs/demonware-lobby-messages.md`
  - `docs/demonware-storage-playlists.md`
  - `docs/demonware-next-steps.md`

Some focused documents predate the latest runtime fixes and may still describe storage as unimplemented or the RPCN HMAC as the active blocker. This file is the authoritative current status until those documents are refreshed.
