# Storage service & playlist / MOTD file format

How the lobby bootstrap actually gets playlists and message-of-the-day. Derived
from `default_mp.elf` (MW2 = IW4) strings and the `iw6_ds_ps3.pdb` symbols
(Ghosts = IW6, same `bdStorage` design). **No packet decryption required** — the
playlist payload is a plaintext Infinity Ward config that Demonware Storage
merely hosts as an opaque file.

## The core realization

Demonware Storage is a dumb file host. `bdStorage` exposes:

```
bdStorage::getFile(const char* filename, bdFileData&, const bdUserAccountID&)   // per-user file
bdStorage::getPublisherFile(const char* filename, bdFileData&)                  // title-global file
bdStorage::listAllPublisherFiles(...)
bdStorage::listFilesByOwner(...)
bdStorage::removeFile(...)
```

MW2 downloads its playlists and MOTD as **publisher files** (title-global,
read-only to clients). The returned `bdFileData` is just:

```
bdFileData {
  void*    m_fileData;   // raw file bytes
  unsigned m_fileSize;
}
```

So the server's job for playlists is: return the **raw bytes of a text file**.
The parsing/΅meaning is entirely client-side.

## bd struct layouts (from iw6 PDB, confirmed field order)

`bdFileInfo` (used by list operations / metadata):

| offset | member | type |
|-------:|--------|------|
| 8   | `m_fileID`       | u64 |
| 16  | `m_createTime`   | u32 |
| 20  | `m_modifedTime`  | u32 (sic) |
| 24  | `m_visibility`   | enum (0=PUBLIC, 1=PRIVATE) |
| 32  | `m_ownerID`      | u64 |
| 40  | `m_fileName`     | char[128] |
| 168 | `m_fileSize`     | u32 |

`bdFileData` (used by getFile / getPublisherFile — the download result):

| offset | member | type |
|-------:|--------|------|
| 8  | `m_fileData` | void* (raw bytes) |
| 16 | `m_fileSize` | u32 |

The MW2 result wrapper is `bdGetFileResult` (`bdGetFileResult.cpp`), whose
`handleResult` copies the downloaded bytes into a client-supplied buffer
("Buffer for downloaded file must not be NULL"). On the wire the result is bd
task-serialized (same tagged encoding as `internal/auth/lsg_protocol.go`
`bdByteWriter`): the file bytes are delivered as a blob/string result field.

## Which files the client requests

Confirmed filename/token strings:

- `playlists.info` (a.k.a. `playlistFilename`) — the playlist definition file.
- MOTD — separate publisher file; errors `Error getting motd`,
  `Motd was %i bytes`, `Unable to retreive MOTD`, `Insufficient space for motd`.
- `%s_version.txt` — version gate file.
- Profile / stats come through a different path (`bdStatsInfo`,
  `LiveStorage_*`), not the storage file service.

> The exact request order and filenames are best captured at runtime: when
> RPCS3 hits the emulator, the storage request payload contains the requested
> filename as a bd string. Logging the decrypted storage request in
> `handleTask` (service 10) will confirm the precise sequence for this title
> build.

## playlists.info format (IW4 line-based grammar)

The MW2 playlist parser is **line/token based**, not key=value. Errors like
`Playlist error: line %i: found 'ranked' flag outside of playlist definition`
reveal the grammar. Structure:

```
version <n>

playlist <id>
    name <playlistName>
    description <language> <text>
    maxparty <n>
    minparty <n>
    numrounds <n>
    requiredDlcPack <n>
    unlockxp <n>
    lootgroup <name>
    ranked            # flag (no arg)
    nojip             # flag: no join-in-progress
    noloop            # flag (a.k.a. nolooping)
    partyteams        # flag

    gametype <name>
        hardcore      # flag, gametype-scoped
        teambased     # flag, gametype-scoped
        script <name>
        <rule tokens...>   # arbitrary "field value" rules, added to rules buffer
```

Scope rules enforced by the parser (from the error strings):

- **playlist-scoped** flags/commands: `ranked`, `nojip`, `noloop`,
  `partyteams`, `lootgroup`, `maxparty`, `minparty`, `numrounds`,
  `requiredDlcPack`, `unlockxp`.
- **gametype-scoped** flags/commands: `hardcore`, `teambased`, `script`.
- **global / any scope**: `version`, `playlist`, `gametype`, `name`,
  `description`.
- Rule lines (`Adding '%s' to playlist %i rules` / `gametype %s rules` /
  `global rules`) are `dvar value` pairs written into fixed-size rules buffers.
  Unknown tokens → `ERROR: Unknown playlist field '%s'`; a non-string field
  name → `Must use a string as the name of a playlist field`.

Weighting: playlists carry per-entry weights (`selectedWeight`, "total weight
for this playlist is %i"); the client randomly chooses map/gametype entries by
weight (`Playlists: Choosing next playlist`, "pool of %i total weight").

## Implementation path (server side)

1. **Log the storage request** (service 10) in `handleTask` to capture the
   real filename(s) and operation ID the client sends. Currently every storage
   op returns `bdErrorNoFile` (`lsg_protocol.go:338`).
2. **Serve `playlists.info`** as a publisher-file `getPublisherFile` result:
   bd-serialize the raw text bytes as the file blob with `bdErrorNone`.
3. **Author a minimal `playlists.info`**: one `version`, one `playlist` with a
   `name`, a `gametype` (e.g. `war`/TDM), and a `maps`/rule line. A community
   IW4/MW2 playlist file works verbatim since the format is identical.
4. **Serve MOTD** similarly (small text blob) to clear `Unable to retreive
   MOTD`.
5. Verify against the client sequence, then move to profile/stats
   (`bdStatsInfo`) which is a separate service path.

## Tooling notes (for reproducing this analysis)

- The system `objdump` (binutils 2.42) is **x86-only** and cannot disassemble
  the PPC64 ELF (`can't disassemble for architecture UNKNOWN`). Use
  `llvm-objdump-18 --triple=powerpc64-unknown-linux default_mp.elf`.
- The Ghosts PDB is fully symbolized: inspect struct layouts with
  `llvm-pdbutil-18 dump --types --type-index=<idx> --dependents iw6_ds_ps3.pdb`.
  Resolve forward refs (`forward ref (-> 0xXXXX)`) to the real definition index.

## Cross-references

- LSG task channel + `bdByteWriter` encoding: `demonware-lsg.md`
- Overall flow: `demonware-flow.md`
- Code: `internal/auth/lsg_protocol.go` (`handleTask`, `bdServiceStorage`)
