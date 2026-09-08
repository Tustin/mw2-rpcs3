# MW2 PS3 EZ Patch `.cbo` research

## Summary

MW2's `ez_patch.cbo` begins with a fixed-size, big-endian `0xB14`-byte index used by the PS3 online-update path. It is not itself a fastfile and is not executed as native PowerPC code. The index controls whether additional `ez_*` fastfile zones are loaded and maps as many as 64 logical filenames to offsets later in the CBO, making the file a packed container for downloaded content.

No authentic `.cbo` sample is currently present in the repository or captures, so the field names below are inferred from code behavior. The top-level layout and validation checks are high confidence; the meaning of most bytes in the 44-byte records remains tentative.

## Client workflow

1. At startup, the client constructs `<game update directory>/ez_patch.cbo` and attempts to read it.
2. It reads `0xB14` bytes and validates the leading fields.
3. A valid index is copied into persistent memory; a nonzero entry count enables EZ Patch lookup/loading.
4. During database initialization, the client conditionally adds EZ Patch zones:
   - `ez_ui_mp`
   - `ez_ui_<language>_mp`
   - `ez_common_mp`
   - `ez_common_<language>_mp`
5. File opens can consult the CBO's filename table. A matching record returns the shared CBO file descriptor plus a per-record base offset, allowing normal streaming code to read an embedded file from the container.
6. The online-update state machine can fetch `%s_version.txt`, compare its decimal version with the local CBO version, download `%s.cbo` over HTTP, write it to the update directory, and reload the local structure.

The retail host/path strings are:

- host: `web1.ps3.iw4.iwnet.infinityward.com`
- path prefix: `/ez_patch/%s`
- version filename: `%s_version.txt`
- content filename: `%s.cbo`

The downloader uses PS3 `cellHttp` and is independent of Demonware LSG storage services.

## Download invocation and server integration

The client owns the update schedule; the Demonware server does not need to send a message or storage response to trigger a CBO download.

- Multiplayer startup calls the local CBO loader at `0x285620`.
- That loader backdates the last-check timestamp by `600000` milliseconds, making the first online-update check immediately eligible.
- The normal online frontend pump calls the update state machine at `0x285E18` once the local controller is signed in and the required online/matchmaking state is ready.
- The periodic starter at `0x285BC0` allows another check after approximately ten minutes.
- Console commands including `downloadezpatch` and `xcheckezpatchversion` provide manual/debug entry points.

The playlist can set the existing `ezpatch` dvar to `1` to ensure the feature is enabled after playlist application. This enables the client path but does not redirect traffic into a Demonware LSG handler. The HTTP request still targets the hard-coded retail hostname unless DNS or the ELF is changed.

To serve an update from this project:

1. Include `ezpatch 1` in the playlist configuration.
2. Redirect `web1.ps3.iw4.iwnet.infinityward.com` to the custom server through controlled DNS/hosts resolution, or patch the hostname in the ELF.
3. Expose a plain HTTP listener, normally on port 80, alongside the Demonware services.
4. Implement the expected `/ez_patch/<name>_version.txt` route and return a decimal version newer than the locally loaded CBO patch version.
5. Implement `/ez_patch/<name>.cbo` and return the generated CBO bytes.
6. Confirm that the client writes the result to `/dev_hdd0/game/BLUS30377/USRDIR/ez_patch.cbo` and reloads it.

The exact `<name>` substitution remains unknown and must be recovered from the state-machine formatting calls or observed with network instrumentation. The initial server implementation therefore accepts any nonempty filename ending in `_version.txt` or `.cbo` under `/ez_patch/`.

### Initial download-only test implementation

The repository now includes:

- `ezpatch/ez_patch.cbo`: a `0xB14`-byte header/index fixture with format version `269`, content version `0`, patch version `1`, and zero entries.
- `ezpatch/ez_patch_version.txt`: the decimal version response `1` for inspection/reference.
- `internal/ezpatch`: runtime generation and HTTP handlers for wildcard EZ Patch filenames.
- `rule ezpatch 1` in `playlists.info`.

The server routes return:

```text
GET /ez_patch/*_version.txt -> 200 text/plain, body "1"
GET /ez_patch/*.cbo         -> 200 application/octet-stream, 2836-byte test CBO
```

The response is generated from the same constants used to create the checked-in fixture, preventing accidental stale or malformed test bytes. For an unmodified client, configure `MW2_HTTP_ADDR=:80`; the default `:8080` listener will not receive the retail URL's implicit port-80 request.

This first CBO intentionally has zero entries, so successful download/write is the only expected result. It should not attempt to load an embedded EZ fastfile.

## Confirmed top-level format

All integer fields are expected to be big-endian on PS3.

```c
#define MW2_CBO_FORMAT_VERSION 269
#define MW2_CBO_HEADER_SIZE    0x14
#define MW2_CBO_ENTRY_SIZE     0x2C
#define MW2_CBO_INDEX_SIZE     0xB14
#define MW2_CBO_MAX_ENTRIES    64

typedef struct Mw2CboEntry {
    uint8_t bytes[0x2C];
} Mw2CboEntry;

typedef struct Mw2CboIndex {
    uint32_t format_version;       // 0x000: must equal 269 (0x10D)
    uint64_t content_version;      // 0x004: compared with a client minimum/current value
    uint32_t patch_version;        // 0x00C: valid range is 1..65535
    uint32_t entry_count;          // 0x010: zero means no embedded files/EZ zones
    Mw2CboEntry entries[64];       // 0x014..0xB13
} Mw2CboIndex;
```

This layout is exact: `0x14 + 64 * 0x2C == 0xB14`. The full CBO may be larger than `0xB14`; embedded file payloads follow this index and are reached through offsets stored in the records.

### Validation performed by the local loader

The local loader accepts the CBO only when:

```text
patch_version is in [1, 65535]
format_version == 269
content_version >= client_required_content_version
entry_count != 0
```

If any of the first three checks fail, the loader forces `entry_count = 0`. A readable object is still copied into memory, but a zero count disables the EZ zones and filename-table lookup.

The client initially reads and copies exactly `0xB14` index bytes. A short file may leave stack bytes uninitialized because the code checks only that the read count is nonzero, not that it equals `0xB14`; generated files need at least a complete `0xB14` index, followed by any embedded payloads.

## Entry table

The table begins at offset `0x14`, records are `0x2C` bytes, and file lookup compares the requested filename with a string beginning at record offset `+0x04`.

```c
typedef struct Mw2CboEntryTentative {
    uint32_t base_offset;      // returned by lookup and used as a read base
    char filename[0x28];       // NUL-terminated; comparison starts here
} Mw2CboEntryTentative;
```

Evidence for `base_offset`:

- A filename match returns the shared CBO descriptor.
- The lookup result's second word is loaded from record offset `+0x00`.
- Streaming code carries this second word alongside the descriptor and uses it as the embedded file's base position.

The table makes the CBO behave like a small packed-file backend: callers ask to open a normal path, and the file layer can redirect that path to a byte range inside `ez_patch.cbo`.

## What a CBO can likely do

### Confirmed

- Enable or disable EZ Patch content by using a nonzero or zero `entry_count`.
- Advertise a small patch version (`patch_version`) to game/network code.
- Participate in compatibility checks: the value returned from offset `0x0C` is used by party/join code.
- Add the four `ez_*` zones to normal database loading.
- Map named files to embedded offsets in the CBO.
- Let existing filesystem/streaming code read embedded data using the shared CBO descriptor.
- Be downloaded and replaced without shipping a conventional title update.

### Strongly suggested

- Carry one or more complete `.ff` zone images inside the container, referenced by filename-table offsets.
- Override assets from base zones using normal fastfile precedence. The exact override rules are enforced by the regular database loader, not by CBO-specific code.
- Update UI assets and common multiplayer assets. The hard-coded zone names make UI/menu/string/script-table-style updates plausible.
- Supply language-specific variants through the localized EZ zone names.

### Not established

- Arbitrary native code execution.
- A CBO-specific scripting virtual machine.
- Cryptographic signatures, hashes, encryption, or compression at the CBO layer.
- The exact asset types permitted in an EZ fastfile.
- Whether maps or large gameplay fastfiles are practical. The filename table and HTTP downloader support embedded files, but startup only automatically requests the hard-coded EZ zone names.
- Whether all 64 table slots were used in retail files and whether filenames shorter than 40 bytes were required.

Any executable behavior would come from asset types already interpreted by MW2, such as menus or game scripts, subject to the normal fastfile loader and zone naming. The CBO itself is data plus packed-file routing metadata.

## Minimal test file

A safe first test is a structurally valid CBO with zero entries. It should prove header parsing and remain disabled without attempting embedded-file lookup. A second one-entry file is required to exercise EZ zone loading.

```python
import struct

SIZE = 0xB14
blob = bytearray(SIZE)

struct.pack_into(">I", blob, 0x00, 269)       # format_version
struct.pack_into(">Q", blob, 0x04, 0)         # content_version; may need raising
struct.pack_into(">I", blob, 0x0C, 1)         # patch_version
struct.pack_into(">I", blob, 0x10, 0)         # entry_count

with open("ez_patch.cbo", "wb") as f:
    f.write(blob)
```

The `content_version` must be at least the client's runtime threshold. In the analyzed static image that threshold storage is initially zero, but a title-update/platform initialization path may set it. If the test is rejected, instrument the comparison at `0x2857F8`/nearby or begin with `0xFFFFFFFFFFFFFFFF` to isolate that check.

Place the generated file at:

```text
/dev_hdd0/game/BLUS30377/USRDIR/ez_patch.cbo
```

Expected evidence:

- The existing `CELL_ENOENT` open failure disappears from the RPCS3 log.
- `patch_version` becomes `1` through the accessor at `0x2853F8`.
- The game remains on the normal zone-loading path because `entry_count` is zero.
- Changing to a one-entry table should take the EZ zone-loading branch; without a valid embedded zone, regular fastfile errors are expected.

## Embedded-file test plan

Creating a useful CBO requires valid MW2 PS3 fastfiles. Recommended sequence:

1. **Header-only test**
   - Generate the empty CBO above.
   - Confirm acceptance and that EZ zone lookup remains disabled with zero entries.

2. **One-entry routing test**
   - Append a recognizable byte payload after the fixed `0xB14` control block.
   - Set `entry_count = 1`.
   - Set entry `base_offset` to the payload's absolute file offset.
   - Set entry filename at record offset `+0x04` to the exact path requested by the file layer, probably `ez_ui_mp.ff` or its resolved zone-relative form.
   - Trace `sys_fs_cellFsLseek`/`Read` to verify reads occur at the supplied base offset.

3. **Known-fastfile embedding test**
   - Embed a known-good, unmodified small MW2 PS3 `.ff` under an EZ zone filename.
   - This tests routing and format assumptions before attempting custom asset generation.
   - A base-zone file may fail because its internal zone identity does not match the requested EZ name; that failure is still informative.

4. **Custom EZ fastfile**
   - Build or rename a zone internally as `ez_ui_mp`.
   - Start with a harmless observable asset such as a localized string or menu asset.
   - Add localized `ez_ui_<language>_mp` only after the nonlocalized zone works.

5. **HTTP update test**
   - Redirect the hard-coded host or intercept DNS.
   - Serve a decimal version text and CBO via the expected `/ez_patch/` paths.
   - Confirm the client writes the CBO to `USRDIR` and reloads it.

## Important unknowns to resolve experimentally

- Exact requested filename passed to the CBO lookup (`ez_ui_mp.ff`, a zone path, or another normalized form).
- Whether `base_offset` points to a raw fastfile, a per-file header, or aligned data.
- Whether entry offset `+0x00` is always an absolute payload base or can encode flags.
- Alignment requirements for embedded payloads.
- Whether file length is stored elsewhere or inferred from the embedded fastfile/header.
- Whether the CBO can contain multiple zones and ancillary files.
- Runtime value of `client_required_content_version`.
- Exact remote `%s` substitution used for version and CBO filenames.

## Relevant ELF locations

Names are provisional because the retail ELF lacks symbols.

- `0x2853D8`: validates the 1..65535 patch-version range.
- `0x2853F8`: returns the accepted patch version at CBO offset `0x0C`.
- `0x285478`: reports whether the CBO has a nonzero entry count.
- `0x285530`: searches 44-byte filename records and returns descriptor/base offset.
- `0x285620`: reads and validates local `ez_patch.cbo`; copies `0xB14` bytes.
- `0x2858C0`: initializes and drives the PS3 HTTP transaction.
- `0x285BC0`: periodically starts version checks/downloads.
- `0x285D10`: closes/removes/reset CBO state after a write/error path.
- `0x285E18`: online-update state machine, HTTP receive, validation, and file write.
- `0x1E6238`: conditionally appends `ez_ui_mp` and localized EZ UI zones to DB loading.
- `0x1E8F10`: startup sequence that loads normal zones, reads CBO, then adds EZ zones.
- `0x296BD8`: filesystem open path that falls back to the CBO filename table.
- `0x297040`: caches file descriptor/base-offset pairs for streaming.
- `0x297140`: reads streamed data using the selected file backend.

## Confidence assessment

- High: total control-block size, byte order, leading-field offsets, validation constants, 44-byte records, filename offset, hard-coded EZ zone names, HTTP endpoint strings, and packed-file fallback behavior.
- Medium: `entry_count`, `base_offset`, and the conclusion that embedded payloads are fastfiles.
- Low: payload alignment, exact filenames, any flag semantics in `base_offset`, and the full set of asset capabilities.

An authentic retail `ez_patch.cbo` remains the fastest way to settle the remaining layout questions. Until then, the empty-header and one-entry routing tests are low-risk ways to validate the inferred format under RPCS3.
