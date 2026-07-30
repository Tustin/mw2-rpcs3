# MW2 PS3 peer QoS and NAT traversal

This note records the peer-side packet formats recovered directly from the
supplied MW2 PS3 `default_mp.elf`. These datagrams begin after matchmaking
service `5`, operation `5` returns a nonempty candidate list. They are not LSG
task replies and they are not sent to the central matchmaking TCP connection.

## Confidence and implementation boundary

| Finding | Confidence |
|---|---:|
| QoS request and reply field order, sizes, and endianness | >99% |
| NAT-traversal packet field order, size, and endianness | >99% |
| NAT HMAC-SHA1 input and 10-byte truncation | >99% |
| Peer-side handling of packet types `0x0a` through `0x0d` | >95% |
| Retry state machine and 0.9-second interval | >90% |
| Client type-`0x0a` introducer request | >95% |
| Current legacy introducer's exact relay behavior | >99% live wire evidence; implemented |
| Historical production anti-abuse/rate-limit policy | unknown; not invented |
| Live RPCS3 two-client traversal and join | not yet established |

The exact serializers and parsers are in the MW2 ELF. OpenIW8 and the supplied
Ghosts symbols were used only to recover class/function names and to
cross-check the interpretation. Their newer packet layouts must not be copied:
MW2's QoS request and reply are smaller.

The central emulator should return the host's exact common address, generated
8-byte session ID, and 16-byte security key in a find result. The game clients
then perform QoS and direct NAT traversal over their peer sockets. Therefore a
central UDP QoS responder would be architecturally wrong: the selected host
client is the QoS listener.

## Byte order

These packets use the old Demonware `bdBytePacker`, not the typed LSG bit
buffer. The PPC serializer explicitly reverses each multibyte scalar before
copying it to the wire:

- integers and ports are little-endian;
- IPv4 addresses retain network octet order;
- booleans are one byte;
- byte arrays are copied unchanged.

This was verified at the instruction level, not inferred from a newer title.

## QoS request: type `0x28`

Exact size: 17 bytes.

```text
offset  size  encoding  field
0x00    1     U8        packet type = 0x28
0x01    8     LE U64    high-resolution timestamp
0x09    4     LE U32    probe ID
0x0d    4     LE U32    shortened security/session ID
```

For example, timestamp `0x0102030405060708`, probe ID `0x11223344`, and
`secID` value `0xaabbccdd` serialize as:

```text
28 08 07 06 05 04 03 02 01 44 33 22 11 dd cc bb aa
```

Authoritative functions:

- constructors/getters: `0x0042c458..0x0042c4b8`;
- serializer: `0x0042c548`;
- parser: `0x0042c740`.

## QoS reply: type `0x29`

Fixed header size: 18 bytes. Total size is `18 + dataSize`.

```text
offset  size      encoding  field
0x00    1         U8        packet type = 0x29
0x01    4         LE U32    echoed probe ID
0x05    8         LE U64    echoed request timestamp
0x0d    1         U8        enabled flag
0x0e    4         LE U32    data size
0x12    dataSize  bytes     optional listener data
```

The reply parser requires all remaining datagram bytes to equal `dataSize`; a
truncated packet or trailing bytes are invalid. The title's payload setter
limits the complete packet to `0x508` (1,288) bytes, so `dataSize` cannot exceed
1,270 bytes.

Authoritative functions:

- constructors and accessors: `0x0042b988..0x0042ba90`;
- serializer: `0x0042bb70`;
- parser: `0x0042c0d0`.

The listener handler at `0x00426908`:

1. requires an initialized and enabled QoS listener;
2. compares the request's 32-bit `secID` with the listener's configured value;
3. drops a request with an invalid `secID`;
4. copies the request ID and timestamp into a type-`0x29` reply;
5. serializes and sends the reply to the datagram sender.

MW2 helper `0x004266f8` copies the first four raw bytes of the matchmaking
Blob[8] security/session ID into this shortened `secID`; it is not a hash and
does not use the Blob[16] key. Because the serializer converts the resulting
number back to little-endian, those four bytes appear unchanged on the wire.
The host listener derives its configured comparison value with the same
helper. The Ghost PDB independently names this function
`bdQoSProbe::shrinkSecId` and confirms the same four-of-eight behavior. The
newer IW8 request has an additional requesting-data flag and its reply has more
measurement fields. Neither belongs in MW2's packet.

The QoS pump at `0x00427828` uses a 0.9-second retry interval. Initial send plus
retries while the send count is below four produces exactly four transmissions
before timeout/removal. The bandwidth arbitrator replenishes at 0.2-second
intervals.

## NAT-traversal packet

Exact size: 29 bytes.

```text
offset  size  encoding  field
0x00    1     U8        type (0x0a..0x0d)
0x01    2     LE U16    protocol version; constructors write 2
0x03    10    bytes     HMAC-SHA1 truncated to 10 bytes
0x0d    4     LE U32    common-address identifier/hash
0x11    4     bytes     source IPv4
0x15    2     LE U16    source port
0x17    4     bytes     destination IPv4
0x1b    2     LE U16    destination port
```

The parser accepts protocol versions greater than or equal to `2`; packets
created by this client use exactly `2`.

Authoritative functions:

- getters/setters: `0x0044b188..0x0044b1d8`;
- parser: `0x0044b290`;
- serializer: `0x0044b4c0`;
- constructors: `0x0044b778` and `0x0044b800`;
- six-byte IPv4/port codec: `0x003d4da8` and `0x003d4eb8`.

### HMAC

Function `0x00442848` initializes HMAC-SHA1 with a 28-byte NAT-traversal
secret at client-object offset `+0x38`. It processes exactly:

```text
LE U32 identifier
source IPv4 + LE U16 source port
destination IPv4 + LE U16 destination port
```

It emits the first 10 bytes of the HMAC-SHA1 result. Packet type, version,
and the HMAC field itself are not part of the authenticated input.

The crypto wrapper is identified directly by MW2 strings `hmacsha1`,
`bdHMacSHA1.cpp`, and `sha1` at `0x00753134..0x00753154`, referenced by
constructor/process/getData functions `0x0049fee8`, `0x0049fe38`, and
`0x0049fd80`.

The 28-byte NAT-traversal secret is a distinct field in the socket client.
Initialization `0x004432d8` fills it locally using the title's time-seeded
global PRNG before enabling the NAT client. It is not copied from the 16-byte
matchmaking security key. This works because the receiver echoes type `0x0b`
or `0x0d` as `0x0c`, while the initiator verifies its own MAC.

### Peer receive behavior

The receive dispatcher is `0x004486a8`.

- `0x0a`: logged as a server packet received in client code and rejected on
  this path.
- `0x0b`: the client changes the type to `0x0c` and sends the packet to the
  embedded source address.
- `0x0c`: the client recomputes and verifies the 10-byte HMAC, then completes
  the pending traversal identified by the 32-bit identifier.
- `0x0d`: accepted only when the identifier equals the local common-address
  hash; the client changes it to `0x0c` and replies to the actual UDP sender.

This establishes a direct peer path and the peer half of the
introducer-assisted path.

An independent search of the supplied Ghosts executable and PDB found the same
client contract but no `bdNATTravServer`, forwarding loop, lookup table, or
server receive handler. Ghosts `bdNATTravClient::sendStage2` at RVA `0x3816d0`
builds the type-`0x0a` request, while `receiveFrom` at RVA `0x3805f0` performs
the same type-`0x0b` -> `0x0c` and type-`0x0d` -> `0x0c` transitions. Its
packet constructor/parser/serializer are at RVAs `0x387220`, `0x3872c0`, and
`0x387480`.

### Introducer relay, directly observed

A controlled two-socket probe of the still-running legacy endpoint
`185.34.107.128:3074` on 2026-07-28 resolved the former routing ambiguity.
The destination was first learned independently with the endpoint's `0x1e`
public-address exchange. The introducer then:

- successfully processed an exact 29-byte type-`0x0a` packet;
- required little-endian protocol version `>= 2`;
- routed to the embedded destination IPv4 and little-endian port at offsets
  `0x17..0x1c`;
- preserved the version, HMAC, identifier, embedded source, and embedded
  destination byte-for-byte;
- changed only the type byte from `0x0a` to `0x0b`; and
- transmitted from the same introducer UDP `3074` endpoint.

Versions `0` and `1` and lengths `28` and `30` were not forwarded. Versions
`2`, `3`, and `65535` were forwarded. Arbitrary identifiers, bogus embedded
sources, and arbitrary HMAC bytes were still forwarded to the exact embedded
destination. This rules out a required identifier-registry lookup for routing
and validation of those opaque fields in the tested path; it does not rule out
optional registration state elsewhere.

This is primary on-wire evidence for the current legacy service, not recovered
server source and not a claim about untested anti-abuse or rate-limit policy.
It is independently consistent with the client trust boundary: the remote
peer echoes the fields and the initiator verifies its own HMAC, which the
introducer cannot generate because the 28-byte key is client-local.

`internal/services/nat/server.go` implements that narrow relay on the primary
UDP listener: strict framing, version `>=2`, embedded-destination routing, and
only the `0x0a` -> `0x0b` mutation. It does not add speculative HMAC,
identifier, source, or endpoint validation.

Because this exact behavior is an unauthenticated UDP forwarding primitive,
runtime wiring is disabled by default. `MW2_NAT_RELAY_ENABLED=true` enables it
for an isolated/trusted two-client lab. It must not be exposed as a general
public forwarder.

The client's type-`0x0a` request construction at `0x00443838` is known:

```text
type         0x0a
version      2
identifier   hash(remote common address)
source       public address from local common address
destination  public address from remote common address
HMAC         local 28-byte secret over identifier/source/destination
UDP target   every configured introducer bdAddr
```

No introducer port is hardcoded in this function; it uses each configured
`bdAddr`. The current legacy service and this emulator use the same primary UDP
`3074` listener for discovery and relay.

## Retry state

Static data and the pump functions show:

- retry interval: 0.9 seconds;
- an entry begins in state 1 with counter zero;
- state 1 performs four direct type-`0x0d` send rounds, then advances to the
  introducer stage when a public address and introducers are available;
- state 2 performs three calls to the type-`0x0a` introducer-send helper, then
  advances to state 3;
- state 3 performs four more direct type-`0x0d` rounds and finally reports
  failure.

The state-2 implementation increments its counter both in the pump and in the
send helper. That literal behavior should be preserved if the state machine is
implemented; it must not be normalized into a guessed retry count.

Relevant functions are `0x00443838`, `0x00443f20`, and the pump surrounding
them. Static constants and labels are at `0x00751928..0x00751958`.

## Relationship to matchmaking

The confirmed client flow is:

```text
service 5 op 5 nonempty reply
  -> completion 0x0031aa58
  -> candidate filtering 0x002fac00
  -> QoS start 0x00320680
  -> peer socket router
  -> selected host/title handshake
```

There is no additional central service-5 join RPC between the search result
and QoS. The repository's encrypted two-client harness proves the server side
through the exact candidate tuple. The peer datagrams documented here are the
next boundary.

## Capture limitation

The supplied 62.655-second retail PCAP ends before a candidate peer is
returned. It contains publisher public-address, NAT classification, bandwidth,
and lobby traffic, but no type-`0x28`/`0x29` QoS pair or 29-byte peer
NAT-traversal exchange. Consequently the layouts above have independent
serializer/parser proof but not a live packet from that capture.

## Safe next work

1. Run two complete MW2 RPCS3 clients against this server.
2. Confirm both receive the exact advertised playlist bytes and that one host session is
   returned unchanged to the seeker.
3. Capture the seeker-to-host type-`0x28` request and type-`0x29` response.
4. For same-LAN/direct tests, verify type-`0x0d` to type-`0x0c`.
5. Redirect the configured introducer hostname and verify the implemented
   `0x0a` -> `0x0b` relay with two clients behind distinct NAT mappings.
6. Compare the following peer-DTLS handshake with
   `demonware-peer-dtls.md`; do not route it through the Demonware LSG
   connection.
