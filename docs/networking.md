# AkurAI VPN — Networking

L3 overlay over a TUN interface named `akurai0`.

## Address plan

| | Value | Notes |
|-|-------|-------|
| IPv4 overlay | `100.88.0.0/16` | Inside the `100.64.0.0/10` CGNAT block, deliberately clear of RFC 1918 LANs so subnet gateways rarely collide. 65 536 addresses; index 0 is the network address. |
| IPv6 overlay | `fd88:akurai::/48` | **Mnemonic.** `akurai` is not valid hex, so the real Unique-Local (RFC 4193) prefix the code uses is `fd88::/48`. 80 host bits. |
| MTU | `1280` | The IPv6 minimum — conservative headroom for the transport + crypto envelope without path-MTU discovery in the MVP. |
| Interface | `akurai0` | Created on every node. |

Allocation helpers live in `akurai-common::overlay`:
`OverlayIpv4::from_index(n)`, `OverlayIpv6::from_index(n)`, and `contains()`
membership tests for both families. The control plane assigns index 1 to itself
by convention.

## Node addressing model

Every node has (design doc §"Core Networking Model"):

- Stable node ID (`NodeId`, 16 bytes, hex).
- Machine identity key (`MachineKey` — placeholder, see `protocol.md`).
- Current session key material _(transport stub in 0.0.1)_.
- Overlay IPv4 and IPv6.
- Internal DNS name, e.g. `laptop.oli.akurai`.
- Allowed inbound routes.
- Advertised routes.
- ACL tags.
- Gateway capabilities.
- Endpoint candidates.
- Relay assignment.

This is the `NodeDescriptor` distributed in the peer map — identity, addressing,
policy, and connectivity hints, never private key material.

## Routes

Default overlay routes installed on every node (`akurai-node::route::overlay_defaults`):

```text
100.88.0.0/16 dev akurai0
fd88::/48     dev akurai0
```

Additional routes (subnet/exit) are pushed by the control plane only after admin
approval — see `gateway-mode.md`.

## Internal DNS (MagicDNS)

`akurai-dns` serves the `*.oli.akurai` zone, resolving overlay names to overlay
IPs from the peer map. It can fold into the control plane initially. In 0.0.1 the
resolver is a stub (`resolve()` returns `None`).

## Hub-routed MVP

The first build tunnels every node to `vpn.olibuijr.com`, which forwards packets
between enrolled nodes. This proves the product and gateway behaviour without
solving internet-scale NAT traversal first; direct peer paths (MVP 3) come after.
