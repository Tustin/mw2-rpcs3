# Live trace: publisher-directory prerequisite

## Result

The 2026-07-28 trace at
`https://stuff.tustin.dev/07a8ccb0-d048-48ec-b89e-5e13acce8ae7`
proves that the type-checking-marker correction is deployed, but the client
still receives storage operation `8` repeatedly and never sends operation `5`.

The remaining failure was not the syntax of `playlists.info`. The server exposed
an incomplete publisher-file directory: it advertised only `playlists.info`,
while MW2 initializes message-of-the-day download states before its playlist
download state.

This milestone advertises and serves both required bootstrap files:

| File | ID | Maximum client buffer | Default content source |
|---|---:|---:|---|
| `messageoftheday.info` | `0x1122334455667789` | `0x100` | `MW2_MOTD`, or the built-in welcome text |
| `playlists.info` | `0x1122334455667788` | `0x20000` | `MW2_PLAYLISTS_FILE` / bundled fixture |

The IDs are server-issued opaque handles. The client selects the matching
filename, copies the associated `u64`, and echoes that ID in operation `5`.

## Runtime evidence

The latest decrypted session contains:

- six operation-8 requests at steps `3`, `4`, `7`, `10`, `13`, and `18`;
- one successful empty owner-list operation `7`;
- no operation-5 request;
- `type_checked=true` on every prepared storage reply;
- a successful authenticated/encrypted LSG session with no reconnect during the
  request sequence.

Every operation-8 reply advertised only:

```text
playlists.info
ID   0x1122334455667788
size 193
```

This excludes the previous type-marker defect as the remaining explanation.

The preserved retail packet capture independently shows a multi-stage publisher
bootstrap. Its server replies include two 445-byte encrypted records before the
157-byte list and 63,373-byte playlist transfer. The exact encrypted content
cannot be recovered without that session key, so the capture is used only for
sequence and frame-size corroboration.

## Static proof from `default_mp.elf`

The binary contains separate bootstrap state objects:

- `0x0030a748` initializes a state for `messageoftheday.info`;
- `0x0030a788` initializes a second MOTD state;
- `0x0030a7c8` initializes the playlist state for `playlists.info`.

The common completion path at `0x00322aa8..0x00322bfc`:

1. deserializes every operation-8 `bdFileInfo`;
2. compares its filename with the state’s requested filename;
3. copies only the matching opaque `u64` file ID;
4. starts operation `5` with that ID.

The MOTD operation-5 consumer in `0x0030b1f0` installs a `0x100`-byte
destination buffer, trims trailing CR/LF bytes, NUL-terminates the result, and
uses it as text. The playlist branch installs a `0x20000`-byte buffer and passes
the downloaded bytes to the playlist parser.

These facts establish that `messageoftheday.info` is a real prerequisite
publisher object and that a short plain-text response is valid. No speculative
MOTD manifest grammar is required.

## Implemented wire behavior

An unfiltered operation-8 reply now contains:

```text
typed u32 result count = 2

typed u32 MOTD byte size
bdFileInfo(messageoftheday.info, MOTD ID)

typed u32 playlist byte size
bdFileInfo(playlists.info, playlist ID)
```

Filename filtering and offset/maximum pagination are applied to that directory.
Operation `5` resolves the requested ID and returns the matching size,
`bdFileInfo`, and typed blob. Unknown IDs still receive `BD_NO_FILE`.

## Verification

Repository tests now exercise:

- both directory entries and their order;
- exact filename filters for MOTD and playlist;
- pagination and empty results;
- operation-5 MOTD metadata/blob;
- operation-5 playlist metadata/blob;
- real encrypted two-client auth/LSG flows that list both entries, retrieve
  MOTD, retrieve the playlist, and then continue into matchmaking.

Live RPCS3 confirmation remains required. The decisive success evidence is an
operation-5 request for the MOTD ID, followed by an operation-5 request for the
playlist ID.
