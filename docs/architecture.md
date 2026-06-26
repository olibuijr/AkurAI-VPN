# AkurAI VPN — Architecture

> A secure, one-touch mesh VPN: a private encrypted L3 overlay with internal
> mesh networking, explicit gateway modes, and a control plane at
> `vpn.olibuijr.com`. Not WireGuard-compatible by design — better tailored than
> a clone.

## What it is

AkurAI VPN is a private encrypted overlay network. Enrolled devices get a stable
overlay IP and an internal DNS name and can reach each other by either, subject
to access-control policy. Devices may optionally act as gateways (subnet, exit,
or public ingress). A control plane manages identity, addressing, and policy; a
relay carries traffic when a direct path is unavailable.

The MVP is **hub-routed**: nodes tunnel to `vpn.olibuijr.com`, which routes
between them. Direct peer-to-peer paths and NAT traversal come later, once the
core VPN behaviour, policy model, and gateway UX are proven.

## Components (crates)

| Crate | Binary | Responsibility |
|-------|--------|----------------|
| `akurai-common` | _(lib)_ | Shared pure-std types: identities, overlay addressing, CIDR, policy, node descriptor, transport stub. |
| `akurai-control` | `akurai-control` | Control plane: enrollment, IP allocation, peer map, ACL, audit, heartbeat, relay assignment. Hosts `vpn.olibuijr.com`. |
| `akurai-node` | `akurai-node` | Node daemon on every device: `akurai0` TUN interface, route application, peer-map watch, gateway modes. |
| `akurai-relay` | `akurai-relay` | Encrypted packet relay fallback — sees only ciphertext. Colocated with the control plane in v1. |
| `akurai-admin` | `akurai-admin` | Admin CLI: pre-auth keys, route approval, ingress, devices, ACL. |
| `akurai-dns` | `akurai-dns` | Internal MagicDNS: `*.oli.akurai` → overlay IP. May fold into the control plane at first. |

## Overlay parameters (fixed)

| Parameter | Value |
|-----------|-------|
| IPv4 overlay | `100.88.0.0/16` |
| IPv6 overlay | `fd88:akurai::/48` (mnemonic; real prefix `fd88::/48`, see `networking.md`) |
| Initial MTU | `1280` |
| TUN interface | `akurai0` |

## Packet flow (internal mesh)

```text
local app
  → akurai0 TUN
  → route lookup by destination overlay IP
  → ACL check
  → peer session lookup
  → direct encrypted QUIC/UDP path if healthy   (later MVP)
  → relay fallback via vpn.olibuijr.com if direct path fails
```

The relay only ever sees ciphertext; it never holds payload keys.

## Control plane vs data plane

`akurai-control` owns control-plane state only — enrollment, identity
registration, overlay IP and DNS allocation, ACL policy, route approval, peer-map
generation, gateway-capability approval, audit events, heartbeat state, and relay
assignment. It does **not** carry data-plane payloads, except when the separate
`akurai-relay` component acts as the ciphertext relay.

## Transport

The data-plane transport (and its cryptography) is an **UNRESOLVED DECISION** —
QUIC + TLS identity vs Noise-over-UDP — and both candidate routes require a
vetted third-party crypto crate, which is in tension with this project's
zero-runtime-dependency principle. The transport and crypto modules are
deliberate stubs in 0.0.1. See `protocol.md`.

## MVP ladder

- **MVP 0 — Planning & threat model.** Architecture, threat model, protocol
  decision, license policy, DNS/deployment plan. _(This scaffold.)_
- **MVP 1 — Single-hub internal VPN.** Enrollment + static peer map; `akurai0`
  TUN; encrypted node→hub tunnel; hub routes between nodes; ACL at hub and node.
- **MVP 2 — Gateway routes.** Subnet advertisements + admin approval + route
  push; exit-gateway opt-in; basic DNS names.
- **MVP 3 — Direct peer mesh.** Endpoint discovery; direct UDP/QUIC attempts;
  relay fallback; path-health scoring; roaming endpoint updates.
- **MVP 4 — Public ingress.** HTTPS ingress on `vpn.olibuijr.com`; route to an
  internal service by node name + port; TLS automation; identity-aware access.

## Status

0.0.1 — scaffold only. Types, module layout, CLI surfaces, and the documented
decisions are in place; no working VPN. See `CHANGELOG.md`.
