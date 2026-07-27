# LSG lobby message framing (bdLobbyConnection)

Working notes on the post-login message layer of the LSG lobby stream (TCP
3074), used to reach playlist/MOTD/profile services. Derived from `default_mp.elf`
(MW2 = IW4) strings and `iw6_ds_ps3.pdb` (Ghosts = IW6) type info, plus runtime
logs from the emulator.

## Transport correction: this is NOT the SCTP bdConnection

DemonWare has two separate transports; do not confuse them:

- **`bdConnection`** — SCTP-style over UDP. Chunked `bdPacket` with
  `bdChunkTypes` (`BD_CT_DATA=2`, `BD_CT_INIT=3`, `BD_CT_INIT_ACK=4`,
  `BD_CT_SACK=5`, `BD_CT_COOKIE_ECHO=13`, …, max 14) and init/cookie/SAck
  handshake. Used for matchmaking/NAT-style traffic, **not** the LSG lobby.
- **`bdLobbyConnection`** — the LSG stream on TCP 3074. Length-prefixed message
  framing with a receive state machine and per-message encryption. **This is
  what our server already speaks.**

The observed post-handshake bytes (4, 10, 18) are `bdLobbyConnection`/
`bdMessage` **service IDs**, not SCTP chunk types and not three peer values from
`bdLobbyServiceType`. In particular, type 18 is greater than the largest SCTP
chunk type and is the DemonWare bandwidth-test service ID.

## bdLobbyConnection (from iw6 PDB)

Receive state machine `m_recvState` (`bdLobbyConnection::RecvState`):

```
BD_READ_INIT = 0
BD_READ_SIZE = 1      // read the length prefix
BD_READ_ENCRYPT = 2   // read the encrypt-type byte
BD_READ_MESSAGE = 3   // read the message body
BD_READ_COMPLETE = 4
```

Relevant members/methods:

- `m_maxSendMessageSize`, `m_maxRecvMessageSize`, `m_recvEncryptType` (u8),
  `m_messageSize` (u32), `m_recvMessage`.
- `sendTask`, `send`, `sendRaw`, `getMessageToDispatch`, `recvMessageSize`,
  `recvEncryptType`, `recvMessageData`, `receivedFullMessage`, `setSessionKey`.

This matches our existing LSG record codec (length prefix, encrypt flag byte,
3DES body). No transport rewrite is required.

## bdMessage (the application unit)

```
bdMessage {
  u8   m_type;             // message type (what we log as outer "type")
  ...  m_payload;          // encrypted service payload (bd byte buffer)
  bool m_payloadTypeChecked;
  ...  m_unencPayload;     // optional unencrypted payload
}
```

The recv dispatcher logs (from the ELF):

```
Received message of type: BD_LSG_SERVICE_TASK_REPLY
Received message of type: BD_LOBBY_SERVICE_TASK_REPLY
Received message of type: BD_LOBBY_SERVICE_PUSH_MESSAGE
Received unknown message type: %u.
Failed to read message type from message.
```

The MW2 receive dispatcher at ELF VMA `0x3f81d0` parses messages arriving at
the **client**, so its labels describe server-to-client replies and control
messages rather than ordinary client service requests. Earlier notes incorrectly
assigned values 1–3 to those labels. Public DemonWare symbols and an independent
implementation agree on the actual `bdLobbyServiceType` values:

| value | `bdLobbyServiceType` name | direction/use |
|------:|---------------------------|---------------|
| 1 | `BD_LOBBY_SERVICE_TASK_REPLY` | normal server task reply |
| 2 | `BD_LOBBY_SERVICE_PUSH_MESSAGE` | asynchronous server push |
| 3 | `BD_LSG_SERVICE_ERROR` | LSG-level error |
| 4 | `BD_LSG_SERVICE_CONNECTION` | server connection-ID response |
| 5 | `BD_LSG_SERVICE_TASK_REPLY` | LSG-level/special task reply |

The names and values are independently present in public `demonware.hpp` type
information and Open BitDemon Emulator's `BdMessageType` enum. This corrects the
prior claim that `BD_LSG_SERVICE_TASK_REPLY = 1`; its confirmed value is **5**.
Value 1 is `BD_LOBBY_SERVICE_TASK_REPLY`.

The dispatcher still supports the conclusion that these reply/control types are
separate from ordinary outgoing service requests. Its exact branch reconstruction
should be revisited with the corrected enum table before relying on the old
encrypt-flag/value mapping.

The useful debug-string VMAs remain:

```
BD_LSG_SERVICE_TASK_REPLY       0x5b18e2
BD_LOBBY_SERVICE_TASK_REPLY     0x5b191a
BD_LOBBY_SERVICE_PUSH_MESSAGE   0x5b196a
"Received unknown message type" 0x5b19f0
"Failed to read message type"   0x5b2598
```

(File offset = VMA − 0x10000. Disassemble with
`llvm-objdump-18 -d --triple=powerpc64-unknown-linux default_mp.elf`.)

## Request dispatch: the message byte is the service ID

Ordinary client requests do not appear to use a generic
`BD_LSG_SERVICE_TASK_REQUEST` outer value. After decrypting and validating the
record HMAC, the first message byte is dispatched directly as a DemonWare lobby
service ID. The remaining payload begins with the task/operation encoding and its
serialized arguments.

Confirmed/relevant service IDs include:

| message byte | service |
|-------------:|---------|
| 3 | Teams |
| 4 | Stats |
| 6 | Messaging |
| 7 | Lobby service / initial LSG authentication |
| 8 | Profile |
| 10 | Storage |
| 12 | Title utilities |
| 18 | Bandwidth test |
| 27 | DML |

An independent implementation performs this dispatch by disabling bd type
checking, reading one `u8` as `LobbyServiceId`, selecting the registered service
handler, then enabling type checking for the service payload.

The resulting direction-dependent framing is:

```
client -> server:
    message byte = service_id
    payload      = task/operation id + serialized arguments

server -> client, normal task:
    message byte = 1  (BD_LOBBY_SERVICE_TASK_REPLY)
    payload      = transaction/result structure

server -> client, LSG-level/special task:
    message byte = 5  (BD_LSG_SERVICE_TASK_REPLY)
```

Bandwidth service implementations specifically create replies with type 5. This
matches the existing special bandwidth path in our emulator, but type `0x12` on
the request side must be interpreted as service ID 18 rather than a connection-ID
registration message.

### Reply-body parsing recovered from the dispatcher

For encrypted type 1, the dispatcher decrypts the body, then reads:

```
u32 transaction_or_task_id
u8  payload_type_marker       // expected value 1
u32 result_header_or_length
... serialized task result bytes
```

The exact semantics of the two `u32` fields still need naming from the send
side, but the layout confirms that the reply's correlation identifier is
inside the encrypted payload rather than in the outer lobby record. The older
notes described an "unencrypted type-2/type-3 path" based on the superseded enum
mapping; that branch must be relabeled against the corrected 1–5 table before
its task-versus-push meaning is considered confirmed.

## Runtime observations (emulator, session 29730)

After the server's connection-ID response, the client sends a burst of service
requests that **retransmit** until acknowledged. Earlier analysis mistakenly
called the observed request with byte 18 a connection-ID message; it is the
bandwidth-test service request. Cores after stripping trailing counter-byte
padding (the last plaintext byte equals the outer IV and repeats to fill the
3DES block):

| service ID | service | core payload | steps seen |
|-----------:|---------|--------------|-----------|
| 10 | Storage | `07c2004000000000860c0000` | 3, 4, 8 |
| 10 | Storage | `c7c10050fadae35e3ed104b808000000c0900100` | 5, 7 |
| 4  | Stats | `07c10038010000002800000040e96b8f7bf94413e002` | 6 |
| 18 | Bandwidth test | `010000000000724c3800000000000dcd40` | 9 |

- The outer IV/sequence increments 1..7 while payloads repeat → the client is
  resending lobby messages it considers unacknowledged. This is lobby/remote-task
  reliability (`bdRemoteTaskManager`, `bdLobbyConnection`), **not** SCTP SAck.
- The `07 c2 00` / `c7 c1 00` prefix is the start of the service/task header
  inside `m_payload` (not a transport chunk header).

## Implications for the current emulator

The current constants/dispatch logic should not be treated as authoritative:

- `lsgInitialType = 7` works because 7 is the LobbyService **service ID** used by
  the initial authentication request, not because 7 is a peer core-message enum.
- `lsgResultReplyType = 1` is a valid normal **response** type, but message type 1
  should not be required as a generic wrapper around client service requests.
- `lsgConnectionIDType = 0x12` conflates service ID 18 (`bdBandwidthTest`) with
  the connection response. The confirmed connection response enum is value 4.
- The server sends the connection-ID response after the initial service-7
  handshake. No evidence currently supports waiting for a later client
  connection-ID registration message before accepting normal service requests.
- `handleLSGMessage` should eventually dispatch the decrypted message byte as
  `serviceID` and pass the remaining bytes to that service's task parser.

These are documented findings only; the implementation has not yet been changed.

## Open questions (next RE targets)

1. The exact MW2 request task header: how operation ID, transaction ID, and the
   serialization-context bits produce the observed `07c2…`/`c7c1…` prefixes.
2. Whether MW2's initial service-7 handshake response uses type 4 exactly as in
   the independent implementation, and the precise typed-u64 body shape.
3. Match each normal reply's transaction identifier to its request and determine
   which correctly framed reply stops retransmission.
4. Revisit the `0x3f81d0` dispatcher branches using the corrected 1–5 enum table
   and label each path without relying on the superseded 1–3 interpretation.

## Cross-references

- Record codec + prior task encoding: `demonware-lsg.md`
- Storage/playlist file format: `demonware-storage-playlists.md`
- Status + history: `CURRENT_PROGRESS.md`
