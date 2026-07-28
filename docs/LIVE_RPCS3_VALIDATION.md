# Live RPCS3 validation runbook

This runbook is the acceptance procedure for the recovered MW2 PS3 control
plane. It deliberately separates proven static/automated behavior from results
that require a fresh RPCS3 run.

Target:

- title: `BLUS30377`;
- update: `1.14`;
- network backend: RPCN;
- first gate: one client through playlist application;
- final gate: two distinct clients through host, find, join, and one match.

Do not commit RPCS3 logs, packet captures, account identifiers, tickets, keys,
or proprietary game files. Keep raw evidence outside the repository until it
has been manually sanitized.

## 1. Preflight

Record privately before testing:

- RPCS3 version and commit;
- firmware version;
- MW2 title/update hashes;
- installed DLC/map-pack inventory;
- RPCN version and server;
- the server's client-reachable IPv4;
- whether both clients are on one LAN or behind distinct NATs.

Use two separate RPCS3 profiles and two separate RPCN accounts for the
two-client stage. Start on one LAN with the introducer relay disabled.

Required server ports:

| Transport | Port | Purpose |
|---|---:|---|
| TCP | 3074 | retail authentication and encrypted LSG |
| UDP | 3074 | public-address discovery, primary classification, optional introducer |
| UDP | 3075 | alternate-source NAT classification |
| TCP | 8080 | health and metrics |

TCP `3075` is an older experimental scaffold and is not part of the retail
acceptance path.

## 2. Start the server

Set the advertised address to the IPv4 that both RPCS3 clients can reach:

```powershell
$env:MW2_NAT_ADVERTISED_IP = "192.168.1.10"
$env:MW2_NAT_RELAY_ENABLED = "false"
$env:MW2_LOG_LEVEL = "debug"
$env:MW2_LOG_SENSITIVE = "true"
go run ./cmd/mw2-server
```

Replace the example address. Do not leave `MW2_NAT_ADVERTISED_IP` blank when
running in Docker.

Before booting MW2, verify:

```powershell
Invoke-WebRequest http://127.0.0.1:8080/healthz
Invoke-WebRequest http://127.0.0.1:8080/readyz
```

Ordinary logs intentionally contain hashes and lengths instead of tickets,
session keys, decrypted payloads, or frame bytes. Raw server capture is
disabled by default. Enable it only for a controlled debugging run:

```powershell
$env:MW2_CAPTURE_ENABLED = "true"
$env:MW2_CAPTURE_DIR = "captures"
```

Treat every resulting file as secret.

`MW2_LOG_SENSITIVE=true` is also test-only. It records tickets, key material,
raw records, decrypted request payloads, and plaintext replies. Redact that log
before sharing it.

## 3. Configure RPCS3 host redirection

Use MW2's per-game custom configuration, Network tab, **IP/Hosts switches**.
Current RPCS3 source parses `host=IPv4` pairs separated by `&&`; it rejects a
pair containing zero or more than one `=`. The parser also supports `*` in a
host pattern, but this runbook uses exact names so unexpected traffic remains
visible.

For a server at `192.168.1.10`, enter one line:

```text
mw2-ps3-auth.mmp3.demonware.net=192.168.1.10&&mw2-ps3-lsg.live.mmp3.demonware.net=192.168.1.10&&mw2-stun.us.demonware.net=192.168.1.10&&mw2-stun.eu.demonware.net=192.168.1.10
```

Replace the address on every pair. The syntax is verified against
[`np_dnshook.cpp`](https://github.com/RPCS3/rpcs3/blob/831a078e3f3bb72faf161e8b1d137e67db55157f/rpcs3/Emu/NP/np_dnshook.cpp#L42-L64).

Keep RPCN itself pointed at the intended RPCN service. The switch list should
redirect only the four MW2 Demonware names above.

## 4. One-client playlist gate

Boot MW2 multiplayer, sign in through RPCN, and select **Play Online**.

The run passes this gate only when all of the following are observed in order:

1. one retail authentication request succeeds;
2. its one-use LSG ticket is consumed;
3. the LSG hello completes;
4. storage service `10`, operation `8` is received;
5. operation `8` returns one `playlists.info` record with the exact byte size
   and SHA-256 loaded by the server;
6. the client sends operation `5` using the advertised 64-bit file ID;
7. operation `5` returns the same metadata and the exact advertised Blob;
8. **Fetching Playlists** completes; and
9. the **Public Playlists** screen contains the fixture row.

The decisive server-side shape is:

```text
op8: count=1, size=N, filename="playlists.info", fileID=X, sha256=H
op5: capacityHint=N, same fileID=X, BlobLength=N, same N raw bytes
```

The leading operation-5 size is a capacity hint. The nested Blob length is the
authoritative raw-byte count; this server emits the actual loaded length for
both fields. The Git blob is 193 bytes with LF endings; a Windows checkout may
appear as 205 bytes after CRLF expansion. Either is valid when metadata and
Blob length match the bytes actually served.

Stop and preserve evidence if operation `5` is not sent. Do not alter neutral
`bdFileInfo` metadata speculatively: the client fetch transition reads only the
exact filename and then the file ID.

## 5. One-client public-search gate

Select the visible fixture playlist. The next central request should be
matchmaking service `5`, operation `5`, with:

```text
reserved=0
queryType=2
maxResults=50
q0=!ranked
q1=selected playlist/game-mode ID
q2=netcode version
q3=owned map-pack flags
q4=playlist version
q5=required free public slots
q6=performance
```

Confirm first that a zero-result reply completes without a remote-task error.
Do not infer equality, mask, or skill comparisons from the seven values; only
`host.openPublic >= q5` is currently justified.

## 6. Two-client host/find gate

With client A hosting and client B searching:

1. A sends service `5`, operation `1`;
2. the server returns one generated Blob[8] session ID and Blob[16] security
   key;
3. A advertises the returned identity in later operation-2 refreshes;
4. B sends the exact operation-5 public query;
5. B receives A's 25-byte CommonAddr, generated ID/key, slot counts, and nine
   title attributes;
6. B accepts the nonempty result without a remote-task error;
7. A refreshes at the recovered 180-second cadence while idle; and
8. A's operation `3`, connection close, or five-minute authenticated-LSG idle
   expiry removes its directory record.

Compare every field with `docs/demonware-matchmaking.md`. Operation `4` is not
required unless the live client actually invokes it.

## 7. Peer-path gate

After B accepts A's candidate, central matchmaking is complete. Subsequent game
connectivity is peer-to-peer, except for optional introducer forwarding.

Expected progression:

1. public-address request `1e 02 00` and nine-byte `0x1f` reply;
2. NAT classification `0 -> 3 -> 2`, with commands `3` and `2` answered from
   alternate UDP `3075`;
3. peer QoS `0x28` request and `0x29` reply;
4. direct NAT traversal `0x0d -> 0x0c`, or introduced
   `0x0a -> 0x0b -> 0x0c`;
5. old-bdDTLS Init, InitAck, CookieEcho, CookieAck;
6. authenticated type-6 Data; and
7. a joined lobby and completed match.

For the first same-LAN run, leave `MW2_NAT_RELAY_ENABLED=false`. Enable it only
when a distinct-NAT run proves the introduced path is necessary. The exact
legacy relay is an unauthenticated forwarding primitive and must remain
restricted to an isolated/trusted lab.

## 8. Evidence ledger

For each run, record a private table:

| Time | Client | Menu state | Endpoint | Direction | Length | Decoded event | Result |
|---|---|---|---|---|---:|---|---|

Also record:

- server commit;
- RPCS3 commit;
- whether the packet came from a server log, server capture, RPCS3 log, or
  PCAP;
- packet/frame number for every claim;
- the SHA-256 of each private raw evidence file; and
- every deviation from the expected order.

Before sharing an excerpt, remove account names, NP IDs, addresses not needed
for the proof, tickets, session keys, security IDs/keys, cookies, and packet
payloads that have not been decoded and reviewed.

## Acceptance

The control-plane milestone is live-confirmed only after the one-client
playlist gate and two-client host/find gate pass. Full matchmaking is complete
only after the peer-path gate reaches a joined lobby and one match without
patching around a failed protocol check.
