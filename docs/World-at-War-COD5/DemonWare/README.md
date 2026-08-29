# DemonWare in World at War (PS3)

This section documents the DemonWare client embedded in the US PS3 release of
Call of Duty: World at War. It describes executable code, RTTI, virtual
addresses, wire serializers, result objects, and game-side call paths.

It intentionally does **not** document a replacement server, database schema,
or emulator implementation. Server behavior is useful only as runtime evidence
when it confirms what the unmodified client sends, accepts, or rejects.

## Canonical images

All addresses in this section are PS3 virtual addresses for one exact image.
They are not file offsets.

| Image | SHA-256 | Entry descriptor | Code entry | TOC |
| --- | --- | ---: | ---: | ---: |
| `BLUS30192-mp.ELF` | `79CA733D01D17821D22620CED23A4B5C6075629B3562674373CE3802DD77BA09` | `0x008886C8` | `0x00010230` | `0x00897620` |
| `BLUS30192-sp.ELF` | `EE35B674E7E8F57567163B50D00E6D47E52A5CDA85B04C9EB7729FDA770D7DAF` | `0x008CB5B0` | `0x00010230` | `0x008DAD48` |
| `EBOOT.ELF` | `8910D88524D03700B987B68B965C41E6D78E480768F65319FB4ED0FAEFB3672D` | `0x00020090` | `0x00010230` | `0x000280B8` |

The identical code-entry value does not make these images interchangeable.
Function descriptors carry an image-specific TOC, and matching virtual
addresses can name different code. An address without an MP/SP/EBOOT qualifier
is incomplete.

## Client architecture

The game uses four distinct networking layers:

1. **PSN/RPCN platform authentication** supplies an NP ticket to
   `bdAuthService`.
2. **DemonWare authentication** returns a PS3 type-19 ticket containing the
   24-byte lobby session key and a separate 128-byte LSG token.
3. **Lobby remote tasks** run over encrypted TCP records and expose services
   such as storage, stats, matchmaking, messaging, and KeyArchive.
4. **Peer networking** uses `bdCommonAddr`, NAT traversal, QoS, socket routing,
   and DTLS session material after matchmaking or invite acceptance.

The 24-byte auth cookie, 24-byte lobby key, 128-byte LSG token, eight-byte
session ID, sixteen-byte peer session key, and DTLS shared key are different
objects with different lifetimes.

## Recovered service and task table

| Client class | Service enum | Operations observed in BLUS30192 | Client purpose |
| --- | --- | --- | --- |
| `bdStats` | `LobbyService.STATS` | `StatsTask.WRITE`; `StatsTask.READ_BY_ENTITY`; `StatsTask.READ_BY_PIVOT_OR_RANK`; `StatsTask.WRITE_MULTIPLE` | MP leaderboards and SP/Zombies map statistics |
| `bdMatchMaking` | `LobbyService.MATCHMAKING` | `MatchmakingTask.CREATE_SESSION`; `MatchmakingTask.UPDATE_SESSION`; `MatchmakingTask.DELETE_SESSION`; `MatchmakingTask.FIND_SESSIONS` | Advertise and discover peer-hosted sessions |
| `bdMessaging` | `LobbyService.MESSAGING` | `MessagingTask.SEND_GLOBAL_INSTANT_MESSAGE` | Native game-invite transport |
| `bdStorage` | `LobbyService.STORAGE` | `StorageTask.UPLOAD_USER_FILE`; `StorageTask.UPDATE_USER_FILE`; `StorageTask.GET_FILE`; `StorageTask.LIST_USER_FILES`; `StorageTask.LIST_PUBLISHER_FILES` | Publisher settings and opaque profile files |
| `bdTitleUtilities` | `LobbyService.TITLE_UTILITIES` | `TitleUtilitiesTask.VERIFY_STRING` | Synchronous generated-name/profanity check |
| `bdKeyArchive` | `LobbyService.KEY_ARCHIVE` | `KeyArchiveTask.WRITE`; `KeyArchiveTask.READ_BY_KEYS`; `KeyArchiveTask.READ_BY_ENTITY` | Typed persistent scalar values |
| `bdPerformance` | `LobbyService.PERFORMANCE` | `PerformanceTask.SUBMIT_PERFORMANCE`; `PerformanceTask.GET_PERFORMANCE_VALUES` | Party-member performance input |
| `bdBandwidthTestClient` | `LobbyService.BANDWIDTH_TEST` | `BandwidthTask.RUN_TEST` | Public-host upload/download measurement |

These are legacy five-bit `bdBitBuffer` tasks. They are not the later
byte-oriented DemonWare protocol used by newer titles.

## Actual ELF evidence

The class and method names are grounded in several independent sources:

- GNU RTTI names such as `bdAuthService`, `bdLobbyConnection`,
  `bdLobbyServiceImpl`, `bdLobbyFile`, and `bdListFilesResult`;
- retained source strings under
  `c:/cod5/cod/codsrc/DemonWare/bdLobby/`;
- vtables and PS3 function descriptors;
- typed constants and service/task IDs in serializer control flow;
- consumer-side structure offsets;
- unmodified-client packet captures and RPCS3 breakpoints.

Names ending in `_candidate` remain high-confidence structural identities
rather than recovered PDB symbols. A matching string or matching address in a
second image is not sufficient proof.

## Documentation map

- [ELF APIs and tables](DemonWare/ELF-APIs.md) — functions, vtables, globals, wrapper
  APIs, and recovered object fields.
- [DemonWare operation lookup](DemonWare/Operations.md) — readable service/task enum
  names, raw wire IDs, and operation meanings.
- [Wire formats and objects](DemonWare/Wire-Formats.md) — typed fields, crypto framing,
  task payloads, result layouts, stats rows, invites, and NAT packets.
- [ELF call-flow charts](DemonWare/Flow-Charts.md) — actual client-side control flow from
  authentication through lobby tasks and peer networking.

## High-value research areas

The current maps are strongest around MP authentication/lobby internals,
cross-image storage, MP matchmaking, native invites, and SP Zombies stats.
Useful next ELF work includes:

- independently mapping the SP auth/lobby classes instead of assuming MP
  addresses;
- locating the SP `LobbyService.STATS` task wrappers that select four- versus
  ten-column row classes;
- recovering complete `KeyArchiveTask.WRITE` field construction;
- naming the unresolved `StatsTask.WRITE_MULTIPLE` entity byte from class or
  enum evidence;
- mapping the full `bdLobbyServiceImpl` factory/service table;
- identifying the exact ownership and lifetime of global service singletons;
- tracing successful peer admission from `Party_StartNetwork` through
  `bdSocketRouter`/DTLS completion.
