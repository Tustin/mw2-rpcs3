# BLUS30192 DemonWare Operation Lookup

The documentation uses symbolic service and task names so call-flow diagrams
and API tables remain understandable without memorizing protocol numbers. This
page is the single lookup for the raw values needed when decoding packets.

Task IDs are scoped to their service. For example, wire task `1` means a stats
write under `LobbyService.STATS`, but a session create under
`LobbyService.MATCHMAKING`.

## Services

| Client class | Service enum | Wire ID | Purpose |
| --- | --- | ---: | --- |
| `bdStats` | `LobbyService.STATS` | `4` | Leaderboard and statistics operations |
| `bdMatchMaking` | `LobbyService.MATCHMAKING` | `5` | Peer-hosted session registration and discovery |
| `bdMessaging` | `LobbyService.MESSAGING` | `6` | Native game-invite transport |
| `bdStorage` | `LobbyService.STORAGE` | `10` | Publisher settings and opaque profile files |
| `bdTitleUtilities` | `LobbyService.TITLE_UTILITIES` | `12` | String verification |
| `bdKeyArchive` | `LobbyService.KEY_ARCHIVE` | `16` | Typed persistent scalar values |
| `bdPerformance` | `LobbyService.PERFORMANCE` | `17` | Party-member performance values |
| `bdBandwidthTestClient` | `LobbyService.BANDWIDTH_TEST` | `18` | Public-host bandwidth measurement |

## Tasks

| Service enum | Task enum | Wire ID | Operation |
| --- | --- | ---: | --- |
| `LobbyService.STATS` | `StatsTask.WRITE` | `1` | Write one leaderboard row |
| `LobbyService.STATS` | `StatsTask.READ_BY_ENTITY` | `4` | Read rows for specific entities |
| `LobbyService.STATS` | `StatsTask.READ_BY_PIVOT_OR_RANK` | `5` | Read a page around an entity or rank |
| `LobbyService.STATS` | `StatsTask.WRITE_MULTIPLE` | `10` | Write repeated leaderboard rows |
| `LobbyService.MATCHMAKING` | `MatchmakingTask.CREATE_SESSION` | `1` | Register a new session |
| `LobbyService.MATCHMAKING` | `MatchmakingTask.UPDATE_SESSION` | `2` | Update a registered session |
| `LobbyService.MATCHMAKING` | `MatchmakingTask.DELETE_SESSION` | `3` | Remove a registered session |
| `LobbyService.MATCHMAKING` | `MatchmakingTask.FIND_SESSIONS` | `5` | Find candidate peer-hosted sessions |
| `LobbyService.MESSAGING` | `MessagingTask.SEND_GLOBAL_INSTANT_MESSAGE` | `8` | Send a native invite message |
| `LobbyService.STORAGE` | `StorageTask.UPLOAD_USER_FILE` | `1` | Upload a named user file |
| `LobbyService.STORAGE` | `StorageTask.UPDATE_USER_FILE` | `2` | Replace an existing user file |
| `LobbyService.STORAGE` | `StorageTask.GET_FILE` | `5` | Fetch a publisher or user file by ID |
| `LobbyService.STORAGE` | `StorageTask.LIST_USER_FILES` | `7` | List files owned by a user |
| `LobbyService.STORAGE` | `StorageTask.LIST_PUBLISHER_FILES` | `8` | List publisher-managed files |
| `LobbyService.TITLE_UTILITIES` | `TitleUtilitiesTask.VERIFY_STRING` | `1` | Check a bounded string |
| `LobbyService.KEY_ARCHIVE` | `KeyArchiveTask.WRITE` | `1` | Write keys and values |
| `LobbyService.KEY_ARCHIVE` | `KeyArchiveTask.READ_BY_KEYS` | `3` | Read named keys |
| `LobbyService.KEY_ARCHIVE` | `KeyArchiveTask.READ_BY_ENTITY` | `4` | Read values for an entity |
| `LobbyService.PERFORMANCE` | `PerformanceTask.SUBMIT_PERFORMANCE` | `1` | Submit performance input |
| `LobbyService.PERFORMANCE` | `PerformanceTask.GET_PERFORMANCE_VALUES` | `2` | Read performance values for users |
| `LobbyService.BANDWIDTH_TEST` | `BandwidthTask.RUN_TEST` | `1` | Run the raw byte-mode bandwidth test |

See [Wire Formats and Objects](DemonWare/Wire-Formats.md) for the fields
serialized by each operation and
[ELF APIs and Tables](DemonWare/ELF-APIs.md) for the corresponding client
functions and addresses.
