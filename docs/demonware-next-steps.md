# Implementation status & next steps

## Working today

- **Auth (stream 9):** request parsed, platform key + LSG session key extracted
  (retail offset 151, RPCN offset 91), 295-byte success response generated with
  a fresh random session key and LSG ticket. Ticket→key mapping stored.
- **LSG hello (stream 11):** ticket consumed, session key recovered, 3DES/HMAC
  record codec works both directions, connection nonce returned.
- **First encrypted message:** type `0x12` connection-ID notification recorded;
  `loggedIn` set.
- Client reaches "Connecting to Matchmaking Server Complete." (`DW_LOBBY_CONNECTED`).

## Known gaps (in flow order)

1. **RPCN LSG request HMAC fails.** In recent runs the RPCN client's second LSG
   record is rejected with `invalid LSG request HMAC` (see CURRENT_PROGRESS log
   lines for `.49229` / `.49397` / `.64437`). The type-`0x12` path works for
   some sessions but the encrypted task record fails HMAC validation. This is
   the current blocker and should be confirmed first: verify the RPCN session
   key offset (91) actually matches the key the client uses for the LSG
   connection, since a wrong key yields exactly this symptom.
2. **Storage service returns no files.** Retail returns a ~63 kB bundle at
   step 10 (`bdStorage`/`bdGetFileResult`). The server currently answers every
   storage op with `bdErrorNoFile`. Playlists and message-of-the-day come from
   here, so lobby population will be empty/failed until real file blobs are
   served.
3. **Playlist / profile / rank tasks unimplemented.** ELF references
   `Error getting playlists`, `%iplaylistIsNew/Old`, matchmaking info, and
   leaderboard/stats results. These ride on the same LSG task channel and are
   not yet handled beyond the default "service not available".

## Recommended next action

Because the capture cannot be decrypted (platform key is not on the wire), the
productive path is **runtime**, not more static pcap work:

1. Reproduce a fresh RPCN session against the dynamic server.
2. Focus on gap #1: instrument `decryptRequest` to log, on HMAC failure, the
   decrypted candidate plaintext for both the primary and pending keys, and the
   RPCN key-offset bytes. Confirm whether offset 91 is correct for the current
   RPCN build or whether the LSG key must instead come from the game ticket
   (offset `0x61`) like retail.
3. Once the first post-login task record validates, log its
   `service_id`/`operation_id` and implement handlers working down the
   sequence: title utilities → DML → storage (playlists/MOTD) → profile/rank →
   create-a-class.

## Cross-references

- Framing / phase overview: `demonware-flow.md`
- Auth byte layout: `demonware-auth.md`
- LSG record codec + task encoding: `demonware-lsg.md`
- Code: `internal/auth/raw_server.go`, `lsg_protocol.go`, `lsg_record.go`,
  `legacy_response.go`
- Fixtures / dead-end key derivation: `internal/auth/derive_capture_key_test.go`
