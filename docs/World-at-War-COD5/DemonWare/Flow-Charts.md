# BLUS30192 DemonWare ELF Call-Flow Charts

These diagrams show the client code in the canonical PS3 executables. Nodes are
functions, in-memory objects, or wire messages used by the game. They do not
model a replacement server or its persistence layer.

Mermaid is used so the same source renders on GitHub and other compatible
Markdown viewers. Diagram labels use the recovered symbolic operation names;
the corresponding numeric wire values are kept in the standalone
[DemonWare Operation Lookup](DemonWare/Operations.md).

## Image and address ownership

```mermaid
flowchart LR
    E[EBOOT.ELF<br/>launcher only<br/>TOC 0x000280B8]
    MP[BLUS30192-mp.ELF<br/>competitive multiplayer<br/>TOC 0x00897620]
    SP[BLUS30192-sp.ELF<br/>campaign/co-op/Zombies<br/>TOC 0x008DAD48]

    E -->|spawns selected game image| MP
    E -->|spawns selected game image| SP
    MP -. addresses never transferred .- SP
```

All three images enter code at `0x00010230`, but they use different entry
descriptors and TOCs. That repeated entry address is not shared function
identity.

## PS3 authentication to lobby connection (MP)

```mermaid
sequenceDiagram
    participant G as Game state 0x0046E440
    participant A as bdAuthService
    participant P as PSN/RPCN NP ticket API
    participant D as DemonWare auth endpoint
    participant C as bdLobbyConnection
    participant L as bdLobbyServiceImpl

    G->>A: create/get auth service (title ID 5087)
    A->>A: 0x00086788 create 24-byte auth cookie at +0xC8
    A->>P: request NP ticket with cookie pointer/length
    P-->>A: NP ticket
    A->>A: 0x000862F0 build message 0x12
    A->>D: PS3 auth request
    D-->>A: type-19 reply: status, seed, 152-byte ticket, 128-byte LSG token
    A->>A: 0x00087808 dispatch reply type
    A->>A: 0x00085FE8 decrypt/parse PS3 ticket
    A->>A: copy ticket lobby key to +0xAC
    A->>C: 0x00086D90 create lobby connection with authInfo
    C->>C: 0x00088E98 copy key to +0x3B8
    C->>C: 0x00088F78 initialize 3DES at +0x2C
    G->>L: start separate lobby-service connection
    L->>C: 0x0008B918 connect with copied auth info
    C-->>L: connection state 2
    L-->>G: DW_LOBBY_CONNECTED
```

The auth cookie decrypts the type-19 client ticket. The lobby key inside that
ticket encrypts subsequent lobby records. The 128-byte LSG token is neither of
those keys.

## Encrypted remote-task lifecycle

```mermaid
flowchart TD
    GW[Game wrapper<br/>LiveStorage / Live_* / Party_*]
    API[bd service serializer<br/>service ID + task ID + typed fields]
    BB[bdBitBuffer<br/>0x0004DD00 / 0x0004DA10]
    RTM[bdRemoteTaskManager_startTask_candidate<br/>MP 0x00081548<br/>SP 0x00081248]
    SEND[bdLobbyConnection_prepareMessage_candidate<br/>MP 0x00089AA0]
    ENC[bdCypher3Des_encrypt<br/>MP 0x0004F618]
    WIRE[Encrypted TCP lobby record]
    RECV[bdLobbyConnection_receiveMessage_candidate<br/>MP 0x0008A748]
    DEC[bdCypher3Des_decrypt<br/>MP 0x0004F4B8]
    DISP[bdLobbyServiceImpl message dispatch]
    ATTACH[bdRemoteTaskManager_handleTaskReply_candidate<br/>MP 0x000812F0]
    POLL[Game live-task poller]
    RESULT[bdTaskResult / concrete result deserializer]

    GW --> API --> BB --> RTM --> SEND --> ENC --> WIRE
    WIRE --> RECV --> DEC --> DISP --> ATTACH --> POLL --> RESULT
```

The pending `bdRemoteTask` owns a normal typed reply buffer at `+0x18` or a
byte-mode LSG result at `+0x1C`. Polling reads state at `+0x14`.

## Publisher-file bootstrap

```mermaid
flowchart TD
    REQ[Game requests MOTD / playlist counts / FFOTD / config]
    START[LiveStorage_StartDWFileFetch]
    LIST[bdStorage list publisher files<br/>StorageTask.LIST_PUBLISHER_FILES]
    LISTRES[bdListFilesResult_deserialize<br/>typed size + bdLobbyFileHeader rows]
    SCAN[Game scans exact requested filename]
    GET[bdStorage get file by ID<br/>StorageTask.GET_FILE]
    FILE[bdLobbyFile_deserialize<br/>header + BLOB]
    APPLY{Fetch type}
    MOTD[Trim, compare, apply MOTD]
    COUNTS[Parse aggregate and indexed player counts]
    FF[Load FFOTD / settings]
    CFG[Process online config]

    REQ --> START --> LIST --> LISTRES --> SCAN
    SCAN -->|file ID found| GET --> FILE --> APPLY
    APPLY --> MOTD
    APPLY --> COUNTS
    APPLY --> FF
    APPLY --> CFG
```

Relevant wrapper pairs:

| Stage | MP | SP |
| --- | ---: | ---: |
| request localized MOTD | `0x004585D0` | `0x0034D178` |
| shared fetch starter | `0x00458AB0` | `0x0034D668` |
| start publisher-file list | `0x0047BEB0` | `0x0036EC60` |
| poll/scan list | `0x0047B6D0` | `0x0036E480` |
| poll downloaded file body | `0x0047BA80` | `0x0036E830` |

## User-file lifecycle

```mermaid
flowchart TD
    GAME[Game profile code]
    LIST[StorageTask.LIST_USER_FILES<br/>list by authenticated owner]
    HEADERS[bdListFilesResult<br/>file IDs and names]
    CHOICE{Named file exists?}
    GET[StorageTask.GET_FILE<br/>get body by file ID]
    READ[bdLobbyFile<br/>header + BLOB]
    NEW[StorageTask.UPLOAD_USER_FILE<br/>upload named file]
    QUERY[bdQueryResult<br/>returned u64 file ID]
    UPDATE[StorageTask.UPDATE_USER_FILE<br/>existing ID + replacement BLOB]
    POLL[32-entry Live task table<br/>0x18 bytes per slot]

    GAME --> LIST --> HEADERS --> CHOICE
    CHOICE -->|yes| GET --> READ --> GAME
    CHOICE -->|no| NEW --> QUERY --> GAME
    GAME -->|later write with known ID| UPDATE --> POLL --> GAME
```

MP and SP both use the literal filenames `mpdata` and `badmpdata`, but that
matching spelling does not prove the blobs have the same internal layout.

## Stats and leaderboard flow

```mermaid
flowchart TD
    END[Match result produced by game]
    T1[StatsTask.WRITE<br/>one board row]
    T10[StatsTask.WRITE_MULTIPLE<br/>repeated bulk rows]
    R4[StatsRow4 serializer<br/>SP 0x00333FC8]
    R10[StatsRow10 serializer<br/>SP 0x003360F0]
    READ[Leaderboard UI refresh<br/>MP 0x00440890]
    TASK4[StatsTask.READ_BY_ENTITY<br/>entity read]
    TASK5[StatsTask.READ_BY_PIVOT_OR_RANK<br/>pivot/rank read]
    PAGE[Leaderboard page result<br/>MP 0x00440378]
    BASE[bdStatsInfo_deserialize<br/>entity/rating/rank/name]
    D4[4-column deserialize<br/>MP 0x002100E8<br/>SP 0x00336490]
    D10[10-column deserialize<br/>MP 0x00442A10<br/>SP 0x00336C78]

    END --> T1
    END --> T10
    T1 --> R4
    T1 --> R10
    T10 --> R4
    T10 --> R10
    READ --> TASK4 --> PAGE --> BASE
    READ --> TASK5 --> PAGE
    BASE --> D4
    BASE --> D10
```

The concrete C++ row type, not the task operation alone, controls the column
count. SP `StatsTask.WRITE` has been captured with a four-column row, while
`StatsTask.WRITE_MULTIPLE` can invoke a virtual concrete serializer.

## Matchmaking discovery to peer-network start (MP)

```mermaid
flowchart TD
    REGISTER[Game builds session registration]
    CREATE[bdMatchMaking_createSession<br/>0x00077570<br/>MatchmakingTask.CREATE_SESSION]
    UPDATE[bdMatchMaking_updateSession<br/>0x00077560<br/>MatchmakingTask.UPDATE_SESSION]
    SEARCH[Live_StartFindSessions_candidate<br/>0x00470928]
    FIND[bdMatchMaking_findSessions<br/>0x00077550<br/>MatchmakingTask.FIND_SESSIONS]
    RESULT[bdMatchMakingSearchInfo_deserialize<br/>0x0047F820]
    CAND[MatchmakingCandidatePool_add<br/>0x001E30F8]
    QOS[bdQoSProbe / NAT traversal]
    OK[QoS success callback<br/>0x00477E98]
    FAIL[QoS failure callback<br/>0x00477DD8]
    PUMP[Live_PumpMatchmaking_candidate<br/>0x00449100]
    FILTER[0x001E5B30 ping/validity filter]
    BEST[0x001E92D8 choose surviving host]
    COPY[0x00448588 copy party/session state]
    NET[Party_StartNetwork_candidate<br/>0x001F0B50]

    REGISTER --> CREATE
    REGISTER --> UPDATE
    SEARCH --> FIND --> RESULT --> CAND --> QOS
    QOS --> OK --> PUMP
    QOS --> FAIL --> PUMP
    PUMP --> FILTER --> BEST --> COPY --> NET
```

A successful `MatchmakingTask.FIND_SESSIONS` reply is only a candidate offer.
Static evidence reaches peer-network start; it does not show a later DemonWare
operation that proves the peer join completed.

## Native game-invite flow

```mermaid
sequenceDiagram
    participant S as Sending game
    participant M as bdMessaging
    participant B as DemonWare messaging backend
    participant L as Receiving bdLobbyServiceImpl
    participant G as Receiving game invite code

    S->>M: build nested "invite" BLOB
    M->>M: 0x0007AB68 MessagingTask.SEND_GLOBAL_INSTANT_MESSAGE
    M->>B: context, BLOB, routing flags, recipient IDs
    B-->>L: encrypted lobby message type 2
    L->>L: 0x0004E480 consume m_typeChecked
    L->>L: 0x0007AEE0 read class discriminator 0x28
    L->>L: deserialize sender record and typed BLOB
    L->>G: MP 0x00469B50 receives original nested BLOB
    G->>G: MP 0x00445BC8 parses invite/name/0x24/0x31/final bit
    G-->>G: native popup_invite
    G->>G: MP 0x004465C0 accept selected invite
    G->>G: MP 0x00448588 Live_HandleInvite
    G->>G: start normal party peer-network transition
```

SP independently serializes the same `0x31` join-block ordering and its native
acceptance path reaches the same kind of party-network transition; MP addresses
above are not transferred to SP.

## Peer addressing and secure transport

```mermaid
flowchart TD
    SESSION[Session ID 8 B + session key 16 B]
    COMMON[bdCommonAddr<br/>3 local + 1 external + NAT type]
    REGISTER[bdSocketRouter_registerSessionKey_candidate<br/>MP/SP 0x00062D58]
    PROBE[bdQoSProbe_probe<br/>MP/SP 0x000601F8]
    NAT[bdNATTravClient_connect_candidate<br/>MP/SP 0x00071418]
    DIRECT[Direct traversal probes]
    INTRO[Introducer fallback]
    ROUTER[bdSocketRouter]
    DTLS[bdDTLSConnection handshake]
    ASSOC[DTLS association shared key<br/>MP 0x00066530]
    PEER[Peer game datagrams]

    SESSION --> REGISTER --> ROUTER
    COMMON --> PROBE --> NAT
    NAT --> DIRECT --> ROUTER
    NAT --> INTRO --> ROUTER
    ROUTER --> DTLS --> ASSOC --> PEER
```

The DTLS association derives a separate 24-byte shared key and initializes its
own 3DES state. It is not the lobby session key.
