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

The observed outer message types (4, 10, 18) are `bdLobbyConnection`/`bdMessage`
types, not SCTP chunk types (type 18 > 14, so it cannot be a chunk type).

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

The MW2 receive dispatcher at ELF VMA `0x3f81d0` gives the concrete incoming
reply values. The record reader stores the encrypt flag at object offset
`+0x24`; the dispatcher only accepts values 1 and 2, then branches on the
flag's boolean value:

| encrypt flag | incoming message type | dispatcher label |
|-------------:|----------------------:|------------------|
| 1 | 1 | `BD_LSG_SERVICE_TASK_REPLY` |
| 0 | 2 | `BD_LOBBY_SERVICE_TASK_REPLY` |
| 0 | 3 | `BD_LOBBY_SERVICE_PUSH_MESSAGE` |

Types other than 1–3 take the `Received unknown message type: %u` path. This
settles the server's result-reply constant: `BD_LSG_SERVICE_TASK_REPLY = 1`.
The observed client request values 4, 10, and 18 are separate outgoing/request
message types and are therefore not expected in this incoming-reply switch.

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
inside the encrypted payload rather than in the outer lobby record. The
unencrypted type-2/type-3 path reads a `u32` first and then a one-byte payload
marker before exposing the remaining bytes to the task or push dispatcher.

## Runtime observations (emulator, session 29730)

After the connection-ID message (type 18) the client sends a burst that
**retransmits** until acknowledged. Cores after stripping trailing
counter-byte padding (the last plaintext byte equals the outer IV and repeats to
fill the 3DES block):

| outer type | core payload | steps seen |
|-----------:|--------------|-----------|
| 10 | `07c2004000000000860c0000` | 3, 4, 8 |
| 10 | `c7c10050fadae35e3ed104b808000000c0900100` | 5, 7 |
| 4  | `07c10038010000002800000040e96b8f7bf94413e002` | 6 |
| 18 | `010000000000724c3800000000000dcd40` | 9 |

- The outer IV/sequence increments 1..7 while payloads repeat → the client is
  resending lobby messages it considers unacknowledged. This is lobby/remote-task
  reliability (`bdRemoteTaskManager`, `bdLobbyConnection`), **not** SCTP SAck.
- The `07 c2 00` / `c7 c1 00` prefix is the start of the service/task header
  inside `m_payload` (not a transport chunk header).

## Open questions (next RE targets)

1. Numeric names for the outgoing/request types 4, 10, and 18. The incoming
   reply values are now known: encrypted LSG task reply = 1, unencrypted lobby
   task reply = 2, and lobby push = 3.
2. The `sendTask` framing: how service id, operation id, transaction id, and the
   serialization-context bits produce the observed `07c2…`/`c7c1…` headers.
3. Match the reply payload's first `u32` to the request-side transaction/task
   identifier and determine which reply stops retransmission for each request.

## Cross-references

- Record codec + prior task encoding: `demonware-lsg.md`
- Storage/playlist file format: `demonware-storage-playlists.md`
- Status + history: `CURRENT_PROGRESS.md`
