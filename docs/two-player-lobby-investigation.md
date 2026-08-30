# Two-player lobby connection investigation

_Last updated: 2026-08-29. This document cross-references the World at War PS3 Demonware research with the current MW2 TU0 implementation and live two-client results. MW2 captures, `default_mp.elf`, and live telemetry remain authoritative where the titles differ._

## Objective

Determine why two MW2 clients that successfully discover one another, complete NAT traversal and QoS, and accept performance replies still do not enter the same title lobby.

The current evidence places the remaining failure inside MW2's post-QoS client state machine. The World at War material supports that boundary and provides a clearer model for the expected transition from a successful matchmaking candidate to peer-network startup.

## Current MW2 evidence boundary

The custom backend and two live clients already complete the following:

1. Both clients authenticate and open independent encrypted LSG connections.
2. Both create service-5 session advertisements.
3. Both receive the same self-inclusive, creation-ordered two-result operation-5 array.
4. The selected peer's `CommonAddr25`, `SecurityID8`, and `SecurityKey16` survive the central response.
5. The clients exchange direct NAT traversal packets.
6. Peer QoS succeeds and the shortened QoS ID matches the advertised `SecurityID8`.
7. Service-17 performance replies are accepted.
8. MW2 reaches accepted-QoS cleanup in `sub_CFF28`.
9. No peer bdDTLS Init is sent.
10. Version-3 telemetry proves the candidate never reaches the lower half of `sub_2FD758`, including address conversion and `sub_CED10`.

The latest status and telemetry are recorded in `CURRENT_PROGRESS.md`, especially the post-QoS analysis and version-3/version-4 instrumentation sections.

## What the World at War documentation establishes

### Matchmaking is discovery, not central lobby membership

World at War uses matchmaking service `5` with these tasks:

| Task | Operation |
| ---: | --- |
| `1` | Create/register a peer-hosted session |
| `2` | Update its advertisement |
| `3` | Delete it |
| `5` | Find candidate peer-hosted sessions |

No central matchmaking join task is documented. Its recovered flow proceeds from a successful find reply into a local candidate pool, peer QoS/NAT work, candidate filtering, host selection, party/session-state copying, and `Party_StartNetwork`.

This agrees with MW2's recovered boundary: there is no additional service-5 join RPC between operation-5 discovery and peer QoS. The generic service-3 session implementation elsewhere in this repository is therefore not evidence that retail MW2 needs a central join request.

### A search result is only a candidate offer

The World at War flow is:

```text
FIND_SESSIONS
  -> deserialize search result
  -> add result to candidate pool
  -> QoS success/failure callback
  -> matchmaking pump
  -> ping/validity filter
  -> choose surviving host
  -> copy party/session state
  -> Party_StartNetwork
```

The important distinction is that successful discovery and successful QoS do not themselves place two players in the same lobby. A local title state machine must promote one retained candidate into party-network startup.

That is closely aligned with the current MW2 failure. MW2 completes discovery and QoS but does not reach the equivalent secure-association/network-start transition.

### The core peer join tuple is stable across titles

World at War matchmaking results contain:

```text
Blob[25]  bdCommonAddr
Blob[8]   session security ID
Blob[16]  session security key
```

Its native invite contains the same values as a 49-byte join block, ordered as:

```text
Blob[8]   session security ID
Blob[25]  bdCommonAddr
Blob[16]  session security key
```

This is strong comparative evidence that the three objects form the portable peer-connection description used after either public matchmaking or invite acceptance. The serialization order can differ between a matchmaking result and a title join structure, so MW2's local copy/conversion step is significant.

MW2 already returns these same three lengths and demonstrates that the address and shortened security ID are consumed by traversal and QoS. The unresolved question is whether the complete tuple, particularly the 16-byte security key and normalized join/session object, is copied into the state consumed by `sub_2FD758` and the socket router.

### Candidate selection remains client-controlled

World at War performs QoS callbacks, ping/validity filtering, and best-host selection in the client before peer-network startup. This supports keeping MW2 operation-5 broad enough to return viable candidates instead of trying to make the backend decide the final host.

MW2 retail evidence already disproves equality filters for game mode, netcode version, playlist version, and performance. The current backend's self-inclusive directory and minimal justified filtering should therefore remain unchanged while diagnosing the post-QoS gate.

### Slot counts describe host state but do not prove membership

Both titles have create/update/delete advertisement lifecycles, while neither recovered service-5 interface shows a central join/member operation. The most likely model is:

1. the host advertises available slots;
2. a seeker discovers and connects directly;
3. title-level party admission changes host state;
4. the host updates advertised open/filled slots.

The observed MW2 operation-2 slot update after apparent join reservation is consistent with this model, but it does not prove that the peer secure association or party admission completed.

### Secure transport follows local promotion

World at War documents this peer path:

```text
SecurityID8 + SecurityKey16
  -> socket-router session-key registration

CommonAddr25
  -> QoS
  -> NAT traversal/address resolution

selected candidate
  -> socket router
  -> bdDTLS handshake
  -> independently derived association key
  -> peer title datagrams
```

MW2's expected peer path is independently recovered as:

```text
16-byte Init
  -> 38-byte InitAck
  -> 177-byte CookieEcho
  -> 114-byte CookieAck
  -> authenticated type-0x06 title data
```

The matchmaking `SecurityKey16` is input material for the peer security map; it is not the 24-byte LSG key and is not itself the final DTLS association key.

## Cross-title mapping

| Stage | World at War evidence | Current MW2 state | Implication |
| --- | --- | --- | --- |
| Register session | Service 5 task 1 | Implemented and live | No change |
| Update/delete | Service 5 tasks 2/3 | Implemented and live | Preserve advertisement lifecycle |
| Find sessions | Service 5 task 5 | Implemented; reciprocal two-result arrays proven | No additional central join task indicated |
| Candidate object | `CommonAddr25 + ID8 + key16`, plus title fields | Same core tuple returned | Verify local tuple normalization/copy |
| Candidate pool | Explicit add after deserialization | Candidate reaches filtering/QoS | Already working through QoS |
| QoS callbacks | Success/failure feed matchmaking pump | Accepted QoS and cleanup proven | QoS is not the current blocker |
| Validity/host selection | Local filter and surviving-host choice | Candidate does not reach lower `sub_2FD758` path | Primary investigation area |
| Party/session copy | Explicit copy before network start | Exact equivalent not yet proven live | Strong candidate for missing state transition |
| Socket-router registration | ID and key registered before DTLS | No Init observed | Confirm ID8/key16 registration call is never reached |
| NAT traversal | Direct or introducer path | Direct traversal succeeds | Address reachability is not the blocker |
| bdDTLS | Begins after router/network start | No type-1 Init | First externally visible missing stage |
| Title lobby admission | Peer datagrams after DTLS | Not reached | Must be investigated only after DTLS starts |
| Native invite | Async messaging push carries same 49-byte tuple | Not required for public matchmaking | Useful alternate-path comparison, not a public-search dependency |

## Most likely failure classes

### 1. Early state gate rejects candidate processing

This is the strongest live conclusion. Version-3 hooks at `0x2FDC00`, `0x2FDC30`, `0x2FDC50`, `0x2FDC6C`, and `0x2FDC90` never execute, although accepted QoS cleanup repeatedly does. The failure must occur before the address-conversion and `sub_CED10` portion of `sub_2FD758`.

The prepared version-4 telemetry targets:

- entry/caller behavior at `0xB3F9C`;
- fallback call at `0x2FDD98`;
- candidate call at `0x2FE95C`;
- state update at `0x2FD830`;
- primary gate through `sub_30CC78` at `0x2FD838`;
- secondary gate at `0x2FD850`;
- the active join-state words and `dword_74C860[0x1B00/4]`.

### 2. Candidate cleanup occurs before promotion

`sub_CFF28` receives the valid 50-entry result-list object and clears the active byte of entries whose `+0x44` value is `-1`. It does not promote a candidate or initiate networking.

The unresolved ownership chain is therefore:

```text
accepted QoS result
  -> retained candidate state
  -> ordinary matchmaking consumer
  -> candidate/session copy
  -> join-state update
  -> sub_2FD758 lower path
```

A consumer may be seeing the wrong active flag, wrong result pointer, stale state, or an already-cleared entry.

### 3. Complete join tuple is not present in the expected local object

Traversal and QoS prove that MW2 consumed the peer endpoint and part of `SecurityID8`. They do not prove that the later join structure contains all 49 bytes in the expected in-memory order.

World at War's invite evidence makes this worth checking explicitly:

- selected `SecurityID8`;
- canonical `CommonAddr25`;
- matching `SecurityKey16`;
- pointer ownership/lifetime after QoS cleanup;
- any title party/session fields copied alongside the tuple.

A malformed tuple would be expected to fail at or after address conversion/router registration, while current telemetry suggests the path is skipped even earlier. It is therefore a secondary check, not the leading hypothesis.

### 4. Host-selection or party-state predicate is unmet

World at War has explicit steps for selecting the surviving host and copying party/session state before network startup. MW2 may require an analogous controller, lobby, party, role, or matchmaking-phase value before entering `sub_2FD758`'s candidate-processing half.

This aligns with the version-4 focus on join-state words and `sub_30CC78` rather than network packet serialization.

### 5. Role asymmetry is missing or differs from retail

Retail shows the later seeker initiating toward the earlier host. The custom backend gives both clients the same creation-ordered list and both can perform peer testing, but the exact title predicate that chooses which client becomes host and which initiates remains unknown.

The backend should not impose requester-relative ordering without evidence. Instead, telemetry should compare the early gate values on both clients and identify whether only one reaches the candidate caller or whether both reject it.

## Hypotheses the World at War material makes less likely

The following should not be changed without new MW2 evidence:

- Adding a central service-5 join RPC.
- Replacing matchmaking with the generic service-3 member-list implementation.
- Changing operation-5 ordering again.
- Excluding the requester's own advertisement.
- Restoring equality filters for game mode, netcode, playlist version, or performance.
- Changing QoS request/reply serialization.
- Changing accepted service-17 replies.
- Making the central server answer direct peer QoS or perform peer DTLS.
- Requiring an asynchronous invite notification for ordinary public matchmaking.

## Investigation plan

### Step 1: Run repaired version-4 file telemetry

The first version-4 SELF did not append gate records: its gate wrapper wrote only to executable-segment scratch memory, so the resulting `qos.bin` contained 78 version-2 records and zero version-4 records. Build, deploy, and hash-verify `files/default_mp_tu0_qos_v4_file.self`, clear stale telemetry, and run the same physical-PS3/RPCS3 two-client scenario.

For every version-4 record, correlate:

- hook ID and original LR;
- input `r3`;
- active join-state pointer;
- first three join-state words;
- `dword_74C860[0x1B00/4]`;
- whether any version-3 downstream hook follows;
- the nearest accepted-QoS/version-2 record in time.

The immediate goal is to name the first condition that differs from the successful branch into the lower candidate path.

### Step 2: Compare both clients' role/state transition

Capture the physical PS3 and RPCS3 network timeline around:

1. operation-5 reply receipt;
2. traversal start;
3. QoS completion;
4. service-17 reply;
5. operation-2 slot update;
6. candidate cleanup;
7. next operation-5 search.

Determine whether the host and seeker perform different operation-2 updates or state transitions. If only RPCS3 can be instrumented, use packet timing and advertised slot changes to infer the physical PS3's role.

### Step 3: Map the MW2 equivalent of World at War's party/session copy

Statically identify the MW2 operation between host selection and `sub_CED10` that copies or normalizes:

```text
SecurityID8 + CommonAddr25 + SecurityKey16
```

Trace writes to the object consumed by `sub_2FD758`, including candidate pointer fields, party/lobby pointers, join-ready byte, and state words tested by `sub_30CC78`.

The target is not to copy World at War addresses or structures, but to use its sequence to label the missing MW2 semantic stage.

### Step 4: Validate the complete selected tuple at the promotion boundary

Once the selected-candidate object is identified, record or inspect:

- all eight security-ID bytes;
- all 25 common-address bytes;
- all 16 security-key bytes;
- selected result index;
- source operation-5 result pointer;
- destination party/session object pointer.

Compare these values to the exact operation-5 response returned by the server. Avoid logging unrelated authentication or LSG keys.

### Step 5: Confirm socket-router registration and first DTLS packet

After the early state gate is corrected or understood, verify the first execution of:

- address conversion;
- `sub_CED10` or its immediate router-registration callees;
- security-map insertion for the selected Blob8/Blob16 pair;
- 16-byte type-1 Init transmission.

Do not proceed to title-lobby reverse engineering until the Init/InitAck/CookieEcho/CookieAck exchange is live.

### Step 6: Trace title-level admission only after DTLS state 3

Once CookieAck establishes the association, capture the first authenticated type-`0x06` payload and identify the title-level party admission exchange. DTLS establishment enables peer title traffic but may not itself mean that the second player is visible in the lobby.

World at War suggests that invite and matchmaking paths converge before peer-network start, so its party-flow names can guide semantic labeling, but MW2 packet bytes and ELF behavior must remain authoritative.

## Expected diagnostic outcomes

| Version-4 result | Interpretation | Next action |
| --- | --- | --- |
| Entry hook never executes | Wrong caller/path assumption | Trace the accepted-QoS consumer and caller of `sub_2FD758` |
| Entry executes but candidate caller does not | Candidate is not promoted or selected | Trace candidate flags/pointers between cleanup and host selection |
| Candidate caller executes but primary gate fails | Join/party state predicate is unmet | Identify the exact `sub_30CC78` input and required state transition |
| Primary gate passes but secondary gate fails | Later role/controller/lobby predicate is unmet | Instrument the branch operands and producer writes |
| Early gates pass and version-3 remains empty | Missing branch/call site in the current static map | Expand hooks between `0x2FD850` and `0x2FDC00` |
| Version-3 begins but no DTLS Init | Tuple conversion/router registration failure | Validate CommonAddr, Blob8/Blob16 map entry, and `sub_CED10` return path |
| DTLS completes but lobby remains separate | Title-level admission failure | Decode the first type-`0x06` party messages |

## Evidence hierarchy and cautions

Use evidence in this order:

1. MW2 retail captures and live custom-server captures.
2. MW2 TU0 `default_mp.elf` static analysis and runtime telemetry.
3. Current MW2 server implementation and regression tests.
4. World at War PS3 documentation for structural comparison.
5. Other titles or generic Demonware projects only as leads.

Do not transfer World at War virtual addresses, title attributes, playlist-field semantics, invite discriminator values, or undocumented QoS layouts into MW2. Its strongest contribution is the ordering of architectural stages and the repeated use of the `SecurityID8 + CommonAddr25 + SecurityKey16` peer join material.

## Static TU0 mapping results

A TU0-only static comparison now maps the important World at War stages to concrete MW2 functions without requiring a live telemetry run.

### The 49-byte join structure is confirmed in MW2

`sub_2FDE58` receives a 49-byte peer join block and copies it verbatim to `dword_74C860 + 0x160`. Its two known callers are native-party/invite paths at `0x2F5304` and `0x2F54E8`, and the third argument records which path supplied it.

`sub_2FDCD8` then copies those exact 49 bytes into the active party/session object at `dword_74CB70 + 8`. The destination's first eight bytes are populated separately with the local user's 64-bit identity by `sub_323448`.

This exactly matches the World at War native-invite structure:

```text
+0x00  SecurityID8
+0x08  CommonAddr25
+0x21  SecurityKey16
```

It strongly confirms that MW2 public matchmaking and native party/invite paths converge on the same peer join material before network startup.

### Public matchmaking calls the network-start routine through local controller selection

After the matchmaking pump calls `sub_2FA008`, `sub_2FE2C0` requires `dword_74C870 + 0x390 == 2`, then scans four 0x48-byte local-controller records at `dword_74CB40`.

A record is eligible only when:

1. its state at `+0x00` is `2`; and
2. its 64-bit identity at `+0x28` equals `qword_1F37488`, the local identity populated by `sub_323448`.

Only then does `sub_2FE2C0` call `sub_2FD758` with the matching local-controller index. This is the MW2 equivalent of World at War's post-QoS matchmaking-pump/host-selection transition.

### The first `sub_2FD758` gates are local platform/title state

Before any peer address conversion or socket-router work, `sub_2FD758` requires:

- `sub_30CC78` to pass. This is true only when the NP state classifier `sub_318188` returns `2`, which occurs when its local state field is `9` and its disabled byte is clear.
- `sub_30CC40` to pass. This accepts local global state values `4` or `6`.
- the object pointer at `dword_74C860 + 0x2124` to reference an object whose byte `+0x0C` is nonzero.
- `sub_2F8E68(controller)` to pass, meaning that controller's 72-byte state record has value `2` at `+0x28`.

These predicates are produced by the PS3 NP/title/controller/party state machines. None reads operation-5 attributes, slot counts, performance values, or another Demonware response field.

### Peer setup occurs only after those gates

Once the local gates pass, `sub_2FD758` performs party/router cleanup and setup, converts peer addresses through `sub_D2468` and `sub_D26E0`, copies active party state, and calls `sub_CED10` at `0x2FDC6C`. This is the first secure-association/network-start transition corresponding to World at War's `Party_StartNetwork` stage.

The existing live evidence that none of `0x2FDC00..0x2FDC90` executes therefore means the failure precedes all server-supplied tuple consumption in this lower path.

### Server-side implication

The static mapping does not reveal a confident custom-server fix. The current server already serializes the matchmaking result in the MW2 order recovered from TU0:

```text
CommonAddr25 -> SecurityID8 -> SecurityKey16 -> slot counts -> attributes
```

TU0 then owns the conversion into the 49-byte join order used by party/network startup. Changing the wire order to match the invite block would be incorrect.

The following server changes remain unjustified:

- adding a central join RPC;
- changing session ordering or self-inclusion;
- changing the generated ID/key lengths;
- changing QoS or service-17 replies;
- fabricating NP, title, controller, or local-party state through matchmaking attributes.

The strongest non-telemetry direction is now to continue static producer analysis for the four local predicates above, especially the transition that sets `dword_74C870 + 0x390` to `2` and the controller record at `dword_74CB40 + index*0x48` to state `2` with the correct identity.

## Working conclusion

World at War and the TU0 static mapping both show that the remaining MW2 issue is not a missing backend lobby-membership RPC. The custom server has fulfilled central discovery and supplies the correct peer tuple components.

The missing transition is local: MW2 must promote the accepted candidate into the correct NP/title/controller/party states before `sub_2FD758` reaches address conversion and `sub_CED10`. Static analysis should continue by tracing the producers of those states; telemetry remains optional rather than the immediate next requirement.

## Primary references

- `CURRENT_PROGRESS.md`
- `docs/demonware-matchmaking.md`
- `docs/demonware-peer-qos.md`
- `docs/demonware-peer-dtls.md`
- `docs/World-at-War-COD5/DemonWare/Operations.md`
- `docs/World-at-War-COD5/DemonWare/Flow-Charts.md`
- `docs/World-at-War-COD5/DemonWare/Wire-Formats.md`
- `docs/World-at-War-COD5/DemonWare/ELF-APIs.md`
