# Service-18 bandwidth bootstrap: verified format and fix

## Outcome

The `Fetching Playlists` stall in trace
`server-9a697e50.jsonl` is not evidence that `playlists.info` failed to parse.
The client never requested either advertised file. It remained in the
mandatory Demonware bandwidth-test prerequisite because the server returned
`bdErrorServiceNotAvailable` (`108`) to every service-18 request.

This milestone implements the two service-18 replies and recognizes the UDP
upload packets. The format is cross-validated by three independent sources:

1. the latest decrypted emulator trace;
2. the successful MW2 PS3 retail packet capture; and
3. the symbol-bearing Ghost server binary/PDB supplied as the preserved
   Demonware reference.

Live RPCS3 confirmation is still required. The implementation is not called
runtime-complete until the new trace shows the acceptance sequence listed
below.

## Evidence identity

| Artifact | SHA-256 |
|---|---|
| latest server trace | `19DFC2D12A463DEA80BEE50B7818ED1076F7F3883842211274BE93E759CED196` |
| `mw2 ps3.pcapng` | `33A3EC8EB0A984DB45FBF5BE491541C7B974B4A6E24EC95A81ACE863D3FAD329` |
| `default_mp.elf` | `5ECAE7AEBDFFA8B5AA62F087A81F1B9C20F9C4B3DBDC4D41C2C00E65F1072041` |
| `iw6_ds_ps3.exe` | `E7E8B2BB531983D4D3986D14DA8D37F3FE6D53F49A67BBAABEC93981AD296636` |
| `iw6_ds_ps3.pdb` | `65F7785084E24D24596EE8AFF2520D2B80EB85DEEC1BA56E44CF26FBD96D098C` |

## What the failed trace proves

The latest run repeatedly sends:

```text
service       18
operation     1 (raw, not type-packed)
payload core  010000000000724c3800000000000dcd40
```

The server repeatedly replies:

```text
message type  5 (BD_LSG_SERVICE_TASK_REPLY)
body          0000000000000000016c00
body bytes    11
wire bytes    25
```

After the eight-byte transaction field, `01 6c00` means rejected=true and
little-endian error `108`. The same phase-1 request continues, proving the
client did not advance.

Storage operation 8 was independently active in the same run:

- both `messageoftheday.info` and `playlists.info` were advertised;
- the replies passed the recovered local decoder;
- the client repeatedly listed the directory;
- no storage operation 5 followed.

That sequence is consistent with another unfinished bootstrap task. It does
not establish a playlist-file parse failure because no playlist bytes reached
the client.

## Recovered service-task envelope

Service 18 is special. Client requests use message/service ID `18` and begin
with raw operation byte `1`. Server replies use message type `5`, not the
normal typed task-reply message type `1`.

Every type-5 body begins with:

```text
offset  size  field
0x00    8     untyped little-endian transaction ID
0x08    ...   phase-specific result
```

The current implementation uses transaction ID zero, matching the default
service-task reply behavior and the already accepted rejection path.

## Phase 1: request reply

The Ghost PDB identifies
`bdBandwidthTestClient::handleRequestReply` at image RVA `0x35dec0`.
Decompilation shows this exact success body after the transaction ID:

```text
offset  size  field
0x08    1     rejected (0 = success, 1 = error)
0x09    4     m_packetSize
0x0d    4     m_numPackets
0x11    4     m_senderInitialWait, milliseconds
0x15    4     m_sendDuration, milliseconds
0x19    4     m_receiverInitialWait, milliseconds
0x1d    4     m_receiveDuration, milliseconds
0x21    4     m_lingerDuration, milliseconds
0x25    2     destination UDP port, little-endian
0x27    4     destination IPv4, network octet order
0x2b    8     bandwidth-test token
```

Total type-5 body: 51 bytes.

The successful MW2 PS3 capture independently supplies the title-specific
values:

- destination `209.170.122.250:3074` in the historical run;
- five UDP datagrams;
- exactly 512 bytes per datagram;
- first datagram about 500 ms after the success reply;
- sequence numbers `0..4`;
- about 400 ms between datagrams, completing in about two seconds;
- token `00 01 02 03 04 05 06 07` at UDP offsets `4..11`.

The implemented phase-1 result is therefore:

```text
transaction ID       0
rejected             0
packet bytes         512
packet count         5
initial delay        500 ms
send duration        2000 ms
receiver wait        10000 ms
receive duration     5000 ms
linger duration      500 ms
port                 primary NAT UDP port (normally 3074)
IPv4                 MW2_NAT_ADVERTISED_IP
token                0001020304050607
```

The names above are present verbatim in the symbol-bearing client's diagnostic
format string. The first four values are independently measurable in the MW2
capture. The final three are server-selected timing parameters and are unused
by this upload-only test; the implementation uses the preserved Demonware
reference values.

The 51-byte body plus the existing encrypted LSG envelope produces a 65-byte
wire record, exactly matching the successful retail capture.

`MW2_NAT_ADVERTISED_IP` is reused deliberately: it is already required for
Docker and names the client-reachable host that owns published UDP 3074. For a
native run without that setting, the accepted TCP connection's concrete local
IPv4 is used.

## UDP upload

The client sends five packets to the advertised endpoint:

```text
offset  size  field
0x00    4     sequence, little-endian (0..4)
0x04    8     token 0001020304050607
0x0c    500   test payload
```

Total: 512 bytes.

The primary NAT listener already owns UDP 3074. It now recognizes this exact
shape, logs sequence and sender, and intentionally sends no UDP response.
The upload-only client measures the sends and reports its results in phase 2.

## Phase 2: finalize reply

The successful retail capture shows a larger 41-byte client wire record after
the fifth UDP datagram. The Ghost function
`bdBandwidthTestClient::finalizeTest` constructs a 21-byte request core:

```text
u8 operation = 1
u32 result[5]
```

After 3DES padding, the decrypted payload exposed by this server is 27 bytes.
That distinguishes finalize from the 19-byte padded phase-1 request.

`bdBandwidthTestClient::handleFinalizeReply` at RVA `0x35dce0` consumes:

```text
u8 rejected
u32 result[5]
```

The server returns success plus five neutral zero results:

```text
u64 transaction = 0
u8 rejected = 0
u32 result[5] = 0
```

Total type-5 body: 29 bytes. The encrypted record is 49 bytes, exactly matching
the successful retail capture.

## Runtime acceptance gate

After deploying this milestone, one clean join attempt should show:

1. service 18 phase `request`;
2. response payload length `51`, message type `5`, encrypted frame length `65`;
3. UDP bandwidth sequences `0`, `1`, `2`, `3`, and `4`, each 512 bytes;
4. service 18 phase `finalize`;
5. response payload length `29`, message type `5`, encrypted frame length `49`;
6. no further phase-1 service-18 retry;
7. storage operation `5` for `messageoftheday.info`, followed by operation `5`
   for `playlists.info` (or a precise new failure after the bandwidth task).

If steps 1-5 occur but operation 5 still does not, the next trace will finally
isolate a storage-directory acceptance problem. Before those steps occur,
changing playlist bytes is not evidence-driven.

## Confidence

- Service-18 root cause in the failed trace: **99%**
- Phase-1 and finalize body grammar: **98%**
- MW2 packet count/size/timing/port/token: **98%**
- This milestone removes the currently observed blocker: **90%**, pending the
  live acceptance gate above
- Full matchmaking completion after this patch: not claimed until the client
  downloads the files and reaches the matchmaking create/find lifecycle
