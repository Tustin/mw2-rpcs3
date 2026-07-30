# Implementation status and next live steps

## Working or statically validated

- Dynamic RPCN authentication, one-use LSG tickets, 3DES/HMAC record handling,
  and the hello/connection response work in prior live runs.
- Captured service IDs and operation IDs now decode correctly:
  - storage `10/8` and `10/7`;
  - stats `4/4`;
  - bandwidth `18/1`, whose operation byte is raw rather than type-packed.
- The two-phase bandwidth upload bootstrap is implemented from the
  symbol-bearing client parser and successful MW2 PCAP: 65-byte request reply,
  five 512-byte UDP uploads, then a 49-byte finalize reply.
- Storage `10/8` and `10/5` replies match their retail consumers.
- The bundled `playlists.info` bytes are valid for the retail parser and
  Public Playlists feeder.
- Matchmaking service `5` operations `1..5` have recovered request schemas.
- Create/update/delete and exact op-5 find-sessions queries are implemented
  against shared retail-LSG state.
- Exact op-1 ID/key, op-2/op-3 mutation, and zero/nonempty op-5 reply layouts
  are covered by golden and two-connection lifecycle tests.
- Exact v2 public-address and NAT-classification requests/replies are
  implemented on primary UDP `3074` and alternate-source UDP `3075`.
- Exact peer QoS `0x28`/`0x29` and NAT-traversal `0x0a..0x0d` packet codecs
  are recovered directly from the MW2 ELF. They are peer traffic, not central
  discovery replies.
- The current legacy introducer's strict 29-byte relay was directly probed and
  is implemented: version `>=2`, embedded-destination routing, only
  `0x0a` -> `0x0b` mutation, and primary UDP `3074` as the source.
- The complete old-bdDTLS peer packet layer is recovered through canonical
  Init, InitAck, CookieEcho, CookieAck, Error, authenticated Data, and replay
  handling. It is peer traffic; no central join RPC exists between the
  candidate result and this handshake.

## Important live boundary

The latest live run still did not send storage `10/5` or any matchmaking
service-5 request. It repeatedly sent the phase-1 bandwidth request because
the deployed server returned error 108. The replacement flow is statically and
capture validated but has not yet passed a fresh RPCS3 run. Automated tests
and Ghidra evidence therefore establish wire compatibility, not end-to-end
RPCS3 completion.

The latest Linux deployment advertised the canonical LF fixture as 193 bytes,
which is correct. A Windows checkout may occupy 205 bytes after CRLF expansion;
the protocol must advertise and return the exact bytes actually loaded. The
absence of operation `5`, not the 193-byte length, is the remaining live
failure.

## Next checkpoints

1. Start the current server build and capture one fresh RPCS3 login.
2. Redirect both `mw2-stun.*` names and live-confirm the `0x1f` public-address
   reply plus the primary/alternate-source `0x15` classification replies.
3. Confirm service `18/1` produces a 51-byte phase-1 reply, UDP sequences
   `0..4`, then a 29-byte finalize reply without another phase-1 retry.
4. Confirm storage `10/8` advertises both `messageoftheday.info` and
   `playlists.info`, with each exact loaded byte size, ID, and SHA-256.
5. Observe storage `10/5` for both files, verify each advertised file ID,
   serve the exact blobs, and confirm the Public Playlists row appears.
6. Select the row and confirm the exact service-5 op-5 request from
   `demonware-matchmaking.md`.
7. Verify zero- and nonempty-result responses complete without a remote-task
   error.
8. Run two distinct clients through create -> find -> update -> delete and
   compare every request/result with the recovered schemas.
9. Capture and compare the post-find type-`0x28`/`0x29` QoS and
   type-`0x0d`/`0x0c` direct-traversal packets with
   `demonware-peer-qos.md`. Do not infer the seven-field retail filtering
   policy from field names alone.
10. Redirect the introducer endpoint and live-confirm the implemented
   type-`0x0a` -> type-`0x0b` relay with clients behind distinct mappings.
   Enable `MW2_NAT_RELAY_ENABLED` only for that isolated/trusted lab.
11. Compare the canonical type-`1..6` peer flow with
    `demonware-peer-dtls.md`, then verify authenticated title traffic,
    teardown, and a completed match.

## Cross-references

- Authoritative status: `../CURRENT_PROGRESS.md`
- Storage/playlist protocol: `demonware-storage-playlists.md`
- Retail matchmaking protocol: `demonware-matchmaking.md`
- Public-address/NAT protocol: `demonware-ip-discovery.md`
- Peer QoS/NAT-traversal protocol: `demonware-peer-qos.md`
- Peer DTLS protocol: `demonware-peer-dtls.md`
- LSG framing and service dispatch: `demonware-lsg.md`
