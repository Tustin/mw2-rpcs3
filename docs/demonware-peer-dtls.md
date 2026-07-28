# MW2 PS3 peer DTLS handshake

This note records the packet boundary immediately after a matchmaking
candidate passes QoS and NAT/address resolution. The supplied MW2 PS3
`default_mp.elf` shows that the next protocol is the title's old peer-to-peer
`bdDTLS` association. It is not another Demonware service-5 task and it does
not pass through the central LSG TCP connection.

## Confidence and server boundary

| Finding | Confidence |
|---|---:|
| Peer-only transport and packet-type dispatch | >99% |
| Common header layout and byte order | >99% |
| Init, InitAck, CookieEcho, and CookieAck canonical layouts | >95% |
| Error packet and authenticated Data wire layout | >99% |
| Data HMAC scope, Blob8 XOR transform, and padding | >99% |
| 16-bit sequence expansion and 32-packet replay window | >95% |
| Peer source/destination behavior | >95% |
| Blob8/CommonAddr25/Blob16 roles | >90% |
| Retry counts, intervals, and acceptance states | >90% |
| Live RPCS3 two-client trace | not yet established |

The central emulator's responsibility ends after service `5`, operation `5`
returns the host's exact:

```text
Blob[8]   security/session ID
Blob[25]  CommonAddr
Blob[16]  security key
```

The retail clients resolve a peer UDP address, perform QoS/traversal, and then
run this handshake themselves. A central DTLS responder would be the wrong
architecture.

## Dispatcher and common header

Receive dispatcher `0x0043d6d8` accepts only packet types `1..6`:

| Type | Packet | Handler |
|---:|---|---:|
| `0x01` | Init | `0x0043b668` |
| `0x02` | InitAck | `0x00439e18` |
| `0x03` | CookieEcho | `0x0043c0b0` |
| `0x04` | CookieAck | `0x00439b00` |
| `0x05` | Error | `0x00439950` |
| `0x06` | encrypted Data | `0x0043d378` |

Type `0` and values greater than `6` are rejected. The jump-table branches are
at `0x0043d7f8`, `0x0043d88c`, `0x0043d870`, `0x0043d858`,
`0x0043d83c`, and `0x0043d814`.

Every packet starts with this six-byte header:

```text
offset  size  encoding  field
0x00    1     U8        packet type
0x01    1     U8        protocol version; constructors write 2
0x02    2     LE U16    verification/local tag
0x04    2     LE U16    sequence/secondary tag
```

Header constructor/parser/serializer:

- constructor `0x00440e18`;
- serializer `0x00440ec0`;
- parser `0x004410c8`.

MW2's `bdBytePacker` writes multibyte values little-endian. Byte arrays are
copied unchanged. The parser reads the version, although the recovered
dispatcher path does not visibly reject a value other than `2`; the title's
constructors emit `2`.

All four handshake constructors write the secondary tag at `+0x04` as zero.
Init also writes a zero verification tag. Canonical InitAck output uses its
initiator tag as the header verification tag, and canonical CookieEcho output
uses the nested InitAck responder tag. The repository encoder rejects values
that violate those constructor-proven relations. MW2's low-level header parser
only reads the fields; state handlers apply the relevant tag checks, so this
canonical validation is intentionally stricter than the bare retail parser.

## Init: type `0x01`

Canonical size: 16 bytes.

```text
offset  size  encoding  field
0x00    6     header    type 1, version 2, both header tags zero
0x06    2     LE U16    initiator local tag
0x08    8     bytes     matchmaking Blob[8] security/session ID
```

Parser/serializer/constructor:

- `0x00441298`;
- `0x004413b0`;
- `0x004414f8`.

Send path `0x0043a3b0` transmits Init directly to the resolved peer address
stored by the association.

## InitAck: type `0x02`

Canonical size: 38 bytes.

```text
offset  size  encoding  field
0x00    6     header    verification tag = initiator tag
0x06    4     LE U32    cookie timestamp
0x0a    4     bytes     truncated cookie signature
0x0e    2     LE U16    responder local tag
0x10    2     LE U16    responder local tag, duplicate
0x12    2     LE U16    initiator tag
0x14    2     LE U16    tie/state tag A
0x16    2     LE U16    tie/state tag B
0x18    4     bytes     observed Init-sender IPv4
0x1c    2     LE U16    observed Init-sender port
0x1e    8     bytes     matchmaking Blob[8] security/session ID
```

The two tie/state fields have exact positions and state-machine uses, but their
historical names are not asserted.

Parser/serializer/constructor:

- `0x00442528`;
- `0x004421e8`;
- `0x00441cd8`.

Send path `0x0043b090` sends InitAck to the actual UDP sender of Init and signs
that observed source endpoint into the cookie.

## CookieEcho: type `0x03`

Canonical size: 177 bytes (`0xb1`).

```text
offset  size  encoding  field
0x00    6     header    verification tag = responder tag
0x06    38    bytes     complete InitAck copied verbatim
0x2c    25    bytes     sender's serialized CommonAddr25
0x45    8     bytes     Blob[8] copied from InitAck
0x4d    100   bytes     initiator ECC public key
```

The size is fixed by `6 + 38 + 25 + 8 + 100 = 177`. CommonAddr serializer
`0x003d5f38` emits exactly `0x19` bytes.

Parser/serializer/constructor:

- `0x0043ed30`;
- `0x0043ee88`;
- `0x0043f150`.

Send path `0x00439650` sends CookieEcho to the actual UDP sender of InitAck.

## CookieAck: type `0x04`

Canonical size: 114 bytes.

```text
offset  size  encoding  field
0x00    6     header    verification tag = initiator tag
0x06    100   bytes     responder ECC public key
0x6a    8     bytes     matchmaking Blob[8] security/session ID
```

Parser/serializer/constructor:

- `0x0043e828`;
- `0x0043e920`;
- `0x0043ea18`.

Send path `0x0043a9f0` sends CookieAck to the actual UDP sender of CookieEcho.

The fixed-field parsers prove these canonical sizes, but no explicit
final-offset-equals-datagram-length comparison was identified. The repository
codec intentionally requires the canonical size so captured packets cannot be
misclassified by accepting truncation or unexamined trailing data.

## Error: type `0x05`

Canonical size: 15 bytes.

```text
offset  size  encoding  field
0x00    6     header    type 5, version 2, sequence tag zero
0x06    1     U8        error enum
0x07    8     bytes     matchmaking Blob[8] security/session ID
```

Constructor `0x00440b00`, serializer `0x004409c0`, parser `0x004408b0`, and
handler `0x00439950` establish this fixed layout. Sender `0x004394f0` writes a
zero sequence tag. The handler first requires the association's local
verification tag. Error enum `0` closes the association; other values are
logged/ignored by this build.

## Authenticated Data: type `0x06`

The established association carries title packets in this exact structure:

```text
offset  size       encoding  field
0x00    6          header    type 6, version 2, vtag, low 16 bits of sequence
0x06    8          bytes     first 8 bytes of HMAC-SHA1
0x0e    2          LE U16    transformed-prefix plaintext length E
0x10    align8(E)  bytes     Blob8-XOR transformed prefix plus padding
...     C          bytes     clear title tail
```

The reconstructed title packet is:

```text
LE U16 E
E transformed-prefix bytes
C clear bytes
```

The prefix is padded to an eight-byte boundary with literal `0x01` bytes, then
every padded byte is XORed with the repeated eight-byte security/session ID.
The clear tail is copied unchanged. Despite the class name, this MW2 build
does not apply 3DES to type-6 data; the association's 3DES context is passed to
the codec but never read. A Tiger digest of the expanded sequence is also
computed in both directions but is not consumed by the effective transform.
Newer-title AES/nonce/AAD layouts do not apply.

The sender rejects reconstructed title packets above `0x4ef` bytes. With
`wireSize = titleSize + 14 + pad(E)`, where `pad(E)` is `0..7`, the maximum
canonical wire size is `0x504`. The retail low-level parser is
caller-capacity-driven rather than containing that literal wire ceiling; the
repository parser enforces `0x504` as a stricter canonical/allocation-safety
boundary.

The HMAC key is the 24-byte Tiger-192 result from the ECC shared secret. Its
authenticated input is exactly:

```text
wire[0:6] || wire[16:end]
```

Thus the HMAC excludes both its own bytes at `6..13` and the `E` field at
`14..15`. The parser still checks `E` against the datagram bounds before
transforming. This unusual omission is covered by an explicit regression test;
it must not be silently “fixed” into a different protocol.

Outbound sequence starts at one because the association counter initializes
to zero and is pre-incremented. Only its low 16 bits are carried in the header.
The receiver reconstructs the nearest full 32-bit value around its high-water
mark and maintains a 32-packet bitmap. New packets advance the window;
previously unseen out-of-order packets 1..31 behind are accepted, while
duplicates and packets at least 32 behind are rejected. Authentication and
verification-tag checks happen before replay state is mutated.

Authoritative functions:

- outgoing constructor `0x0043f8f0`;
- serializer/auth transform `0x0043f9f0`;
- parser/auth decode `0x00440200`;
- association handler `0x0043d378`;
- send path `0x004391d8` / `0x00439460`;
- verification/replay gate `0x00438c20`.

The repository implements this as an isolated codec and replay primitive. It
does not yet route reconstructed title messages or claim a first title opcode.

## Security-material roles

The three fields returned by matchmaking have distinct roles:

- Blob8 appears in clear in Init and is repeated through the handshake.
- CommonAddr25 selects/resolves the peer and is included in CookieEcho.
- Blob16 is installed in `bdSecurityKeyMap` under Blob8.

Shared-key setup `0x00438e08` calls key-map lookup `0x0042f478`; absence of the
Blob8 entry fails the association. Direct PPC data flow shows that this MW2
build does not feed the Blob16 contents into the observed session-key
derivation. After lookup, the 16 bytes are copied for diagnostic formatting.
The cryptographic path is:

```text
peer 100-byte ECC public key
  -> 44-byte ECC shared secret       0x0049f5e8
  -> Tiger-192, 24 bytes             0x003db048 / 0x003daea0
  -> type-6 HMAC-SHA1 key
```

Blob16 therefore acts as a key-map authorization/presence gate in this build,
not as the observed DTLS KDF input. This is title-specific and must not be
replaced with a newer-title KDF.

A 3DES context is initialized for the association, but direct type-6
serializer/parser data flow proves that this build's effective title-data
transform is the repeated Blob8 XOR described above.

The InitAck cookie uses a separate process-global 16-byte secret. Sign/verify
functions `0x00441aa0` and `0x00441848` cover the timestamp, five 16-bit tag
fields, and observed peer address; the packet stores four signature bytes.
Blob8 and Blob16 are not part of that cookie input.

## States, retries, and acceptance

Association states:

```text
0  closed
1  waiting for InitAck
2  waiting for CookieAck
3  established
```

- Init and CookieEcho use separate retry counters.
- Senders `0x0043a3b0` and `0x00439650` transmit while the previous count is
  `<= 5`, producing six transmissions total.
- Pump `0x0043a630` retries after more than one second.
- Retry exhaustion closes the association.
- Default receive timeout is 1,800 seconds (`0x00751664`, initialized by
  `0x00438a78`).

InitAck handler `0x00439e18` requires state 1, successful parsing, and a header
verification tag equal to the initiator's local tag. It stores the responder
tag, sends CookieEcho, and enters state 2.

Cookie validation `0x0043a168` requires:

- age no greater than 59 seconds;
- signed embedded address equal to the actual CookieEcho UDP sender;
- valid four-byte cookie signature.

CookieAck handler `0x00439b00` requires successful parsing, the local
verification tag, state 2, a Blob8 entry in the security-key map, and successful
ECC/Tiger/3DES derivation. It then enters state 3 and invokes the established
callback. Type `0x06` title data begins only after that point.

## Live validation

The supplied retail PCAP contains no candidate peer and therefore no peer DTLS
packet. A fresh two-client capture should show:

```text
service 5 op 5 nonempty result
  -> peer QoS / NAT resolution
  -> 16-byte Init
  -> 38-byte InitAck
  -> 177-byte CookieEcho
  -> 114-byte CookieAck
  -> authenticated type-0x06 title data
```

Validate endpoint direction, tags, repeated Blob8, CommonAddr25, and canonical
sizes before interpreting title data.
