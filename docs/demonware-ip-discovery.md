# MW2 PS3 public-address and NAT discovery (UDP 3074/3075)

MW2 uses a compact proprietary Demonware protocol behind the
`mw2-stun.*.demonware.net` names. It is not RFC STUN. Redirect both captured
names to this server:

```text
mw2-stun.us.demonware.net
mw2-stun.eu.demonware.net
```

The primary UDP listener is `MW2_NAT_ADDR` (default `:3074`). The alternate
reply-source listener is `MW2_NAT_ALT_ADDR` (default `:3075`). Their UDP ports
must differ. TCP services may use the same numeric ports.

## Public-address request (`0x1e`)

The request is exactly three bytes:

```text
1e 02 00
```

The primary socket returns exactly nine bytes:

| Offset | Size | Encoding | Meaning |
|---:|---:|---|---|
| `0` | 1 | byte | response type `0x1f` |
| `1` | 2 | little-endian `u16` | version `2` |
| `3` | 4 | IPv4 octets | observed client source IPv4 |
| `7` | 2 | little-endian `u16` | observed client source port |

Captured golden reply:

```text
1f 02 00 18 d8 a2 6f 02 0c
```

## NAT-classification request (`0x14`)

The request is exactly four bytes:

```text
14 02 00 command
```

Only commands `0`, `3`, and `2` are accepted:

| Command | Reply source |
|---:|---|
| `0` | primary socket |
| `3` | alternate-source socket |
| `2` | alternate-source socket |

Every accepted command returns exactly 15 bytes:

| Offset | Size | Encoding | Meaning |
|---:|---:|---|---|
| `0` | 1 | byte | response type `0x15` |
| `1` | 2 | little-endian `u16` | version `2` |
| `3` | 4 | IPv4 octets | observed client source IPv4 |
| `7` | 2 | little-endian `u16` | observed client source port |
| `9` | 4 | IPv4 octets | advertised alternate/source-check server IPv4 |
| `13` | 2 | little-endian `u16` | primary query port |

Captured golden reply:

```text
15 02 00 18 d8 a2 6f 02 0c b9 22 6b 81 02 0c
```

Both alternate commands advertise the same server IPv4 and primary port; the
different UDP source port of the response is the classification signal.

## Client classification state machine

Direct client tracing establishes:

1. command `0` is sent to the primary address; its reply supplies the saved
   observed client endpoint and advertised alternate server endpoint;
2. command `3` is sent to the primary address; a reply whose source IP equals
   the advertised server IP but whose source port differs from the advertised
   primary port produces **Open** NAT;
3. if that test times out, command `2` is sent to the advertised server
   endpoint. Matching the first observed endpoint produces **Moderate** NAT;
   a changed endpoint or final timeout produces **Strict** NAT.

The client does not require two different server IPs. Advertising one server IP
at `3074` and sourcing commands `3`/`2` from that same IP at `3075` satisfies
the exact Open-NAT source check. The client uses a 0.5-second timeout and up to
five resends per stage.

The request constructor/serializer is `0x004259a0` / `0x004259d0`. Response
parser `0x004263c0`, together with address decoder `0x003d4da8`, proves the
field order and endian rules. The supplied PCAP independently confirms the
15-byte response and the primary-3074/alternate-3075 source behavior.

`MW2_NAT_ADVERTISED_IP` is an optional explicit canonical IPv4 address for
native runs. When it is blank, the server uses a specific IPv4 from the
alternate reply-source socket, or derives the local route IPv4 when that
listener is wildcard-bound. The advertised IPv4 at the primary query port must
route back to the primary listener because command `2` is sent to that endpoint.

Docker deployments **must set `MW2_NAT_ADVERTISED_IP` to the host's
client-reachable IPv4 address**. Automatic route discovery inside a container
returns the container address, which is not the address clients need in the
`0x15` reply. Compose fails fast when the variable is absent. Publish/forward
both `3074/udp` and `3075/udp`.

Malformed or truncated packets, trailing bytes, unsupported versions, unknown
commands, and IPv6 senders receive no reply. Replies are sent only to the
datagram sender.

## Scope boundary

The same primary UDP listener also implements the separately proven
introducer relay: an exact 29-byte type-`0x0a`, version-`>=2` packet is sent to
its embedded destination after changing only the type to `0x0b`. That relay is
documented in `demonware-peer-qos.md` and is not part of the `0x1e`/`0x14`
discovery reply formats. It is disabled by default and requires
`MW2_NAT_RELAY_ENABLED=true` in a trusted lab.

The central service does not answer QoS probes, perform the peers' direct
hole-punch exchange, or carry title traffic. Those packets are exchanged by
the game clients after candidate selection.
