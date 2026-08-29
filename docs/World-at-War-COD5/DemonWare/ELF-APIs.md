# BLUS30192 DemonWare ELF APIs and Tables

This page is an address-qualified map of the DemonWare code embedded in the
canonical BLUS30192 executables. MP and SP addresses are separate columns on
purpose. A blank cell means the function has not been independently identified
in that image.

Confidence:

- **confirmed** — exact serializer/control flow, RTTI/vtable, retained source
  evidence, or a verified runtime call path;
- **high** — strong structural identity retained with a `_candidate` suffix;
- **candidate** — unresolved identity that should not be treated as an API
  name.

## PS3 function descriptors

PPU code pointers frequently refer to an eight-byte function descriptor rather
than directly to the instruction address:

```text
descriptor +0x00  code address
descriptor +0x04  TOC address loaded into r2
```

For MP, mapped DemonWare descriptors use TOC `0x00897620`. For SP they use
`0x008DAD48`. Copying only a code address into another image loses the required
TOC context.

## Legacy bit buffer

These entries were independently decompiled in both MP and SP even where their
virtual addresses happen to match.

| API | MP | SP | Confidence | Recovered behavior |
| --- | ---: | ---: | --- | --- |
| `bdBitBuffer_destructor_candidate` | `0x0004D930` | `0x0004D930` | high | Releases the buffer at `+0x08` and clears size/cursor state |
| `bdBitBuffer_writeBits` | `0x0004DA10` | `0x0004DA10` | confirmed | Writes arbitrary widths least-significant-bit first; advances `+0x14` and updates `+0x18` |
| `bdBitBuffer_constructor_candidate` | `0x0004DD00` | `0x0004DD00` | high | Allocates rounded-up bit capacity, stores type-check mode at `+0x21`, and writes the initial mode bit |
| `bdBitBuffer_writeType` | `0x0004E078` | `0x0004E078` | confirmed | Writes a five-bit `bdDataType` value when type checking is enabled |
| `bdBitBuffer_readBits` | `0x0004E0A8` | — | confirmed | Reads LSB-first and advances the read cursor |
| `bdBitBuffer_constructorFromData_candidate` | `0x0004E480` | `0x0004E480` | high | Builds a read buffer and consumes the first bit into `m_typeChecked` |
| `bdBitBuffer_checkType` | `0x0004EAB8` | — | confirmed | Reads and validates a five-bit field tag |

### Partial object layout

| Offset | Field |
| ---: | --- |
| `+0x08` | backing byte-buffer pointer |
| `+0x14` | current bit cursor |
| `+0x18` | maximum written bit cursor |
| `+0x21` | `m_typeChecked` byte |

## Authentication and cryptography (MP image)

The authentication map is currently proven in `BLUS30192-mp.ELF`. Do not
apply these addresses to SP without independent verification.

| MP address | API | Confidence | Evidence |
| ---: | --- | --- | --- |
| `0x0004F4B8` | `bdCypher3Des_decrypt` | confirmed | Sets an eight-byte IV and calls LibTomCrypt CBC decrypt |
| `0x0004F618` | `bdCypher3Des_encrypt` | confirmed | Sets an eight-byte IV and calls LibTomCrypt CBC encrypt |
| `0x0004F7D0` | `bdCypher3Des_init` | confirmed | Finds `3des` and initializes CBC state from a 24-byte key |
| `0x0004F098` | `bdHashTiger192_hashUInt32_candidate` | confirmed | Hashes a reply seed as four little-endian bytes |
| `0x0004EEF0` | `bdAuthService_decryptAuthTicket3DES_candidate` | high | One-shot platform-ticket decryption wrapper |
| `0x000862F0` | `bdAuthService_buildPS3Request_candidate` | high | Builds message `0x12` with request random, title data, and NP ticket |
| `0x00086788` | `bdAuthService_createPS3AuthCookie` | confirmed | Generates exactly 24 alphanumeric bytes at `bdAuthService+0xC8` |
| `0x00085FE8` | `bdAuthService_handlePS3Reply_candidate` | high | Handles reply type 19, decrypts 152 bytes, installs lobby key, reads server ticket |
| `0x00087808` | `bdAuthService_handleAuthReply_candidate` | high | Requires status 700 and dispatches reply types 11 through 21 |
| `0x00087994` | `bdAuthService_authReplyJumpTable` | confirmed | Eleven signed branch offsets indexed by reply type minus 11 |
| `0x000879C0` | PS3/type-19 branch | confirmed | Direct call to `0x00085FE8` |
| `0x000888F0` | `bdAuthTicket_initialize_candidate` | high | Clears the 128-byte base ticket object |
| `0x000889D8` | `bdAuthTicket_deserialize_candidate` | confirmed | Reads magic, title, times, IDs, username, and 24-byte lobby key |
| `0x0008CA28` | `bdPS3AuthInfo_deserialize` | confirmed | Reads the first 17 decrypted bytes into two `u32` and three byte fields |
| `0x00088728` | `bdAuthService_pumpConnection_candidate` | high | Receives one auth message and dispatches it to the auth-reply handler |

Retained GNU RTTI names independently identify `bdCypher3Des` at
`0x00720D90`, `bdHashTiger192` at `0x00720E90`, `bdAuthService` at
`0x0072A060`, and `bdPS3AuthInfo` at `0x0072ABB0`.

### `bdAuthService` partial layout

The object is `0x124` bytes in the mapped constructor at MP `0x000870D8`.

| Offset | Field/evidence |
| ---: | --- |
| `+0x10` | active `bdLobbyConnection*` |
| `+0x18` | shared destination-address object |
| `+0x24` | embedded auth/result object |
| `+0x2C` | start of the separately retained 128-byte LSG token |
| `+0xAC` | 24-byte lobby key as viewed from `bdAuthService` |
| `+0xC8` | 24-byte clear PS3 auth cookie |
| `+0x110` | observed auth status; 700 is success |
| `+0x114..+0x120` | two optional lobby buffer pointer/size pairs |

`0x00086D90 bdAuthService_createLobbyConnection_candidate` uses the optional
buffers when configured; otherwise it selects the default-buffer constructor,
which allocates two 65,535-byte buffers.

## Lobby connection and remote tasks (MP image)

| MP address | API | Confidence | Recovered behavior |
| ---: | --- | --- | --- |
| `0x00088D30` | `bdLobbyConnection_getState` | confirmed | Reads state at `+0x24`; observed 1 connecting, 2 connected, 4 closed |
| `0x00088E98` | `bdLobbyConnection_setSessionKey_candidate` | high | Copies 24 bytes to `+0x3B8` and initializes the cipher at `+0x2C` |
| `0x00089130` | `bdLobbyConnection_constructorWithDefaultBuffers_candidate` | high | Allocates two 65,535-byte buffers |
| `0x00089998` | `bdLobbyConnection_connectWithAuthInfo_candidate` | high | Passes `authInfo+0x88` to the session-key setter |
| `0x00089AA0` | `bdLobbyConnection_prepareMessage_candidate` | high | Frames plain or encrypted lobby records |
| `0x0008A134` | outgoing payload encryption call | confirmed | Calls `bdCypher3Des_encrypt` |
| `0x0008A748` | `bdLobbyConnection_receiveMessage_candidate` | high | Parses records and decrypts encrypted bodies in place |
| `0x0008AA2C` | incoming payload decryption call | confirmed | Calls `bdCypher3Des_decrypt` |
| `0x0008B918` | `bdLobbyServiceImpl_connectWithAuthInfo_candidate` | high | Copies auth info and constructs the separate lobby connection at `+0x4C` |
| `0x0008BBC0` | `bdLobbyServiceImpl_pumpConnection_candidate` | high | Dispatches lobby message types and returns connection state |
| `0x0008C4B0` | `bdLobbyServiceImpl_onConnect` | high | Configures the connection and installs the key from `+0xD8` |
| `0x00081548` | `bdRemoteTaskManager_startTask_candidate` | high | Builds typed service/task envelope and queues the task |
| `0x000818F0` | `bdRemoteTaskManager_startRawTask_candidate` | high | Queues a raw service/task body, used by bandwidth test |
| `0x000812F0` | `bdRemoteTaskManager_handleTaskReply_candidate` | high | Reads typed transaction ID and attaches reply to the pending task |
| `0x000810C0` | `bdRemoteTaskManager_handleLsgTaskReply` | confirmed | Handles byte-mode lobby message type 5 |
| `0x000806F8` | `bdRemoteTask_getStatus` | confirmed | Reads `+0x14` and changes overdue pending tasks to timeout state 3 |
| `0x000806A8` | `bdRemoteTask_getReplyBuffer` | confirmed | Returns typed reply buffer at `+0x18` |
| `0x000806D0` | `bdRemoteTask_getResultBuffer` | confirmed | Returns byte-mode result buffer at `+0x1C` |

The MP global pointer `g_bdLobbyServiceImpl_singleton` is at `0x008AEFC4`.
It resolves to an object with vptr `0x0086B470` and embedded/owned connection
state beginning at object offset `+0x4C`.

### `bdRemoteTask` partial layout

| Offset | Field |
| ---: | --- |
| `+0x14` | state/status |
| `+0x18` | normal typed reply buffer |
| `+0x1C` | processed byte-mode result buffer |
| `+0x28` | task-manager reference used by release |

## Storage APIs

### Low-level task serializers

| Operation | DemonWare operation | MP | SP | Confidence |
| --- | --- | ---: | ---: | --- |
| upload named file | `StorageTask.UPLOAD_USER_FILE` | `0x00084C88` | `0x00084578` | confirmed |
| update existing file | `StorageTask.UPDATE_USER_FILE` | `0x00085540` | `0x00084E30` | high |
| get publisher or user file by ID | `StorageTask.GET_FILE` | `0x000853F8` | `0x00084CE8` | confirmed |
| list files by owner | `StorageTask.LIST_USER_FILES` | `0x00085188` | `0x00084A78` | confirmed |
| list publisher files | `StorageTask.LIST_PUBLISHER_FILES` | `0x00084F80` | `0x00084870` | high |

The SP serializers call `0x00081248
bdRemoteTaskManager_startTask_candidate`. The MP serializers call the separate
MP entry at `0x00081548`.

### Game-side storage wrappers

| Operation | MP | SP | Confidence |
| --- | ---: | ---: | --- |
| start user-file upload | `0x0047B3B8` | `0x0036E168` | confirmed |
| poll upload and copy returned file ID | `0x0047B1B0` | `0x0036DF60` | high |
| start existing-file update | `0x0047B088` | `0x0036DE38` | high |
| start file download by ID | `0x0047B4F8` | `0x0036E2A8` | high |
| start owner file list | `0x0047B5B0` | `0x0036E360` | confirmed |
| start publisher file list | `0x0047BEB0` | `0x0036EC60` | high |
| poll publisher list | `0x0047B6D0` | `0x0036E480` | confirmed |
| poll file body | `0x0047BA80` | `0x0036E830` | high |
| pump new/update selection | `0x00457E18` | `0x0034C9C0` | high |

Both game images use 32 live task slots of `0x18` bytes. The pump selects
`StorageTask.UPLOAD_USER_FILE` for a new file and
`StorageTask.UPDATE_USER_FILE` after an existing `u64` file ID is known.

### Storage result objects

| Result API | MP | SP | Confidence |
| --- | ---: | ---: | --- |
| `bdListFilesResult_deserialize` | `0x000837A0` | `0x00083090` | confirmed |
| `bdLobbyFile_deserialize` | `0x00083FF8` | `0x000838E8` | confirmed |
| `bdLobbyFileHeader_deserialize` | `0x00084440` | `0x00083D30` | confirmed |
| `bdTaskResult_deserializeReply_candidate` | `0x000848C8` | `0x000841B8` | confirmed |
| `bdQueryResult_deserialize` | `0x000E5BE0` | `0x000E4F28` | confirmed |

### `bdLobbyFileHeader` partial layout

| Offset | Size | Field |
| ---: | ---: | --- |
| `+0x08` | 8 | file ID |
| `+0x10` | 4 | first metadata `u32` |
| `+0x14` | 4 | second metadata `u32` |
| `+0x18` | 1 logical | first boolean field |
| `+0x1C` | 1 logical | second boolean field |
| `+0x20` | 8 | owner ID |
| `+0x28` | 128 | bounded filename buffer |
| `+0xA8` | 4 | file size/capacity |

`bdLobbyFile` extends this header with a data pointer at `+0xAC` and an
ownership byte at `+0xB0`.

## Stats and leaderboards

| API | MP | SP | Confidence | Meaning |
| --- | ---: | ---: | --- | --- |
| `bdStatsInfo_deserialize` | `0x00082BB0` | `0x000826D0` | confirmed | Entity ID, rating, rank, name base |
| four-column row deserialize | `0x002100E8` | `0x00336490` | confirmed | Base plus four signed columns at `+0x64..+0x70` |
| ten-column row deserialize | `0x00442A10` | `0x00336C78` | confirmed | Base plus ten signed columns at `+0x64..+0x88` |
| four-column row serialize | — | `0x00333FC8` | confirmed | Rating base plus four signed columns |
| ten-column row serialize | — | `0x003360F0` | confirmed | Rating base plus ten signed columns |
| leaderboard page deserialize | `0x00440378` | — | confirmed | Reads total available then the envelope-supplied row count |
| refresh leaderboard page | `0x00440890` | — | confirmed | Starts `StatsTask.READ_BY_ENTITY` or `StatsTask.READ_BY_PIVOT_OR_RANK` |
| counted-result parser | `0x00077580` | — | confirmed | Accepts discriminators 1, 4, or 5 and reads row count |

MP `0x00081C28` starts `LobbyService.STATS` /
`StatsTask.WRITE_MULTIPLE`, and MP `0x00082F00` writes each bulk row's ID,
entity ID, one byte, virtual field count, and concrete row serializer. SP
captures prove `StatsTask.WRITE_MULTIPLE` repeats rows without a top-level
count.

The task operation does not uniquely select the concrete row type: SP solo
Zombies has sent `StatsTask.WRITE` with a four-column board-1023 row.

## KeyArchive and title utilities (MP image)

| MP address | API | Confidence | Purpose |
| ---: | --- | --- | --- |
| `0x000726A0` | `bdArchiveValue_ctor` | confirmed | Clears the value discriminator |
| `0x000726D8` | `bdArchiveValue_int32_ctor` | confirmed | Stores signed-32 value and update operation as variant 2 |
| `0x00072758` | `bdArchiveValue_deserialize` | confirmed | Reads variant then payload; no update-operation byte in replies |
| `0x00072A28` | `bdArchiveValue_serialize` | confirmed | Writes variant, update operation, then payload |
| `0x0046AA20` | `bdKeyArchive_writeKeys` | confirmed | Key request serializer identified by retained assertion |
| `0x0046B038` | `bdKeyArchive_startReadKeysTask3_candidate` | high | Starts `KeyArchiveTask.READ_BY_KEYS` |
| `0x000744A8` | `bdKeyArchive_startTask4_candidate` | high | Writes entity ID and two booleans for `KeyArchiveTask.READ_BY_ENTITY` |
| `0x0046BEC8` | `bdKeyArchive_parseReadResponse` | confirmed | Parses operation 3/4 key and entity/value tables |
| `0x00085B70` | `bdTitleUtilities_verifyString` | confirmed | Starts `TitleUtilitiesTask.VERIFY_STRING` with a bounded string |
| `0x00085E90` | `bdVerifyStringResult_deserialize` | confirmed | Reads one typed `u32` status |
| `0x0020FD68` | `Live_VerifyStringSync_candidate` | high | Polls synchronously; nonzero means profanity detected |

## Matchmaking and performance (MP image)

| MP address | API | Confidence | Purpose |
| ---: | --- | --- | --- |
| `0x00077408` | `bdMatchMaking_startTask_candidate` | high | Serializes one request and starts `LobbyService.MATCHMAKING` |
| `0x00077550` | `bdMatchMaking_findSessions` | confirmed | `MatchmakingTask.FIND_SESSIONS` |
| `0x00077560` | `bdMatchMaking_updateSession` | confirmed | `MatchmakingTask.UPDATE_SESSION` |
| `0x00077570` | `bdMatchMaking_createSession` | confirmed | `MatchmakingTask.CREATE_SESSION` |
| `0x000778A0` | `bdMatchMaking_deleteSession` | confirmed | `MatchmakingTask.DELETE_SESSION` with eight-byte session ID |
| `0x00078408` | `bdMatchMakingInfo_deserializeBase` | confirmed | Common address, security ID/key, four signed and two unsigned fields |
| `0x0047F820` | `bdMatchMakingSearchInfo_deserialize` | confirmed | Adds nine signed fields; extended field 6 is playlist ID |
| `0x00470928` | `Live_StartFindSessions_candidate` | confirmed | Builds WaW's search request and starts `MatchmakingTask.FIND_SESSIONS` |
| `0x00470CA0` | `Live_StartUpdateSession_candidate` | high | Builds update request |
| `0x00471130` | `Live_StartCreateSession_candidate` | high | Builds create request |
| `0x0007FA28` | `bdPerformance_submitPerformance_candidate` | high | `PerformanceTask.SUBMIT_PERFORMANCE` |
| `0x0007FEA8` | `bdPerformance_getPerformanceValues` | confirmed | `PerformanceTask.GET_PERFORMANCE_VALUES` |
| `0x0007FB90` | `bdPerformance_parsePerformanceValuesReply` | confirmed | Accepts discriminator 2/3 and counted values |

`bdMatchMakingInfo` stores the eight-byte security ID at result `+0x04`,
the sixteen-byte security key at `+0x0C`, and four one-byte session attributes
at `+0x20..+0x23`.

## Messaging, common address, NAT, QoS, and DTLS

| API | MP address | SP address | Confidence |
| --- | ---: | ---: | --- |
| `bdMessaging_sendGlobalInstantMessage_candidate` | `0x0007AB68` | — | high |
| `bdLobbyServiceImpl_deserializePushObject_candidate` | `0x0007AEE0` | `0x0007AEE0` | high, independently checked |
| `bdCommonAddr_serialize_candidate` | `0x00050EC0` | shared routine independently called at SP `0x0033A7A4` | high |
| `bdCommonAddr_fromSerialized_candidate` | `0x00051330` | — | high |
| `bdQoSProbe_probe` / SP `_candidate` | `0x000601F8` | `0x000601F8` | MP confirmed; SP high |
| `bdQoSProbe_probeInternal` / SP `_candidate` | `0x0005F920` | `0x0005F920` | MP confirmed; SP high |
| `bdSocketRouter_registerSessionKey_candidate` | `0x00062D58` | `0x00062D58` | high, independently checked |
| `bdNATTravClient_handlePacket` | `0x00070870` | `0x00070870` | confirmed |
| `bdNATTravClient_connect_candidate` | `0x00071418` | `0x00071418` | high |
| `bdDTLSAssociation_generateSharedKey_candidate` | `0x00066530` | — | high |
| DTLS shared-key installation call | `0x000667BC` | — | confirmed |

The native invite join block is 49 bytes:

| Raw offset | Size | Field |
| ---: | ---: | --- |
| `+0x00` | 8 | session security ID |
| `+0x08` | 25 | serialized `bdCommonAddr` |
| `+0x21` | 16 | session security key |

The embedded `bdCommonAddr` is three local six-byte `bdAddr` values, one
external six-byte `bdAddr`, and one NAT-type byte.

## Bandwidth-test client

`LobbyService.BANDWIDTH_TEST` uses the raw-task starter rather than ordinary
typed request fields.

| MP address | API | Confidence |
| ---: | --- | --- |
| `0x00074C78` | `bdBandwidthTestClient_initialize` | confirmed |
| `0x00075B50` | `bdBandwidthTestClient_start` | confirmed |
| `0x00075318` | `bdBandwidthTestClient_parseBootstrapResult` | confirmed |
| `0x000769C8` | `bdBandwidthTestClient_pumpUpload_candidate` | high |
| `0x00076440` | `bdBandwidthTestClient_pumpDownload_candidate` | high |
| `0x00076010` | `bdBandwidthTestClient_submitFinalReport_candidate` | high |
| `0x00074E50` | `bdBandwidthTestClient_parseFinalReportResult` | confirmed |
| `0x00076D18` | `bdBandwidthTestClient_pump` | confirmed |
| `0x000771A0` | `bdBandwidthTestResult_deserialize` | confirmed |

Partial object fields:

| Offset | Meaning |
| ---: | --- |
| `+0x0C` | initialized flag |
| `+0x10` | state |
| `+0x14` | error |
| `+0x1C..+0x34` | seven bootstrap/configuration `u32` values |
| `+0x74` | server-observed measurement |
| `+0x88` | local measurement / five final measurement words |
