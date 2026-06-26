# AGENTS.md — AkurAI VPN

> The map. Read this first. AkurAI VPN is a secure, one-touch mesh VPN: a
> private encrypted L3 overlay with internal mesh networking, explicit gateway
> modes, a control plane at `vpn.olibuijr.com`, and a ciphertext-only relay
> fallback. Land in the right crate via the tables below — don't grep blind.

## What this is

A **pure-Rust, zero-runtime-dependency** mesh VPN. Devices enroll one-touch, get
a stable overlay IP + internal DNS name, and reach each other subject to ACL
policy. Gateways (subnet/exit/ingress) are first-class and explicit. The MVP is
hub-routed through `vpn.olibuijr.com`; direct peer mesh + relay fallback come
later. Not WireGuard-compatible by design.

## Constitutional principles (do not violate)

1. **Zero runtime dependencies.** Shipped binaries link NO third-party crates —
   `std` only. Internal workspace crates are fine. Dev/test tooling is allowed
   only if it never enters a binary. (Same principle as AkurAI-Framework.)
2. **Do NOT invent cryptography, and do NOT write any crypto.** The transport +
   crypto layer is an **UNRESOLVED DECISION** (`docs/protocol.md`): the plan
   mandates vetted crates (`quinn`/`rustls`/`snow`/`ed25519`), which conflicts
   with principle #1. It is left for Ólafur to decide. Until then the
   transport/crypto modules are clearly-marked stubs and 0.0.1 has **no**
   security properties.
3. **Fail-closed policy.** Deny by default: unknown node → no traffic; unknown
   route → no install; unapproved gateway → reject + audit; missing ACL → deny.
4. **TLS terminates at the nginx edge** on the control plane; the binary speaks
   plain HTTP locally (when the listener exists).
5. **Explicit gateways.** A node never gains a gateway capability without admin
   approval at the control plane.
6. **Small scoped files.** One responsibility per file; index new ones here.
7. **Docs + changelog are first-class.** Every feature ships its `docs/` update
   and its `## [Unreleased]` changelog entry in the same commit.

## Crate map

| Crate | Binary | Owns | Status |
|-------|--------|------|--------|
| `crates/akurai-common` | _(lib)_ | Pure-std core types: `NodeId`, `MachineKey` (placeholder, no crypto), overlay constants + `OverlayIpv4/Ipv6` allocation, `Cidr` membership, policy (`Tag`/`Principal`/`GatewayMode`/`Route`/`AclRule`/`Policy`), `NodeDescriptor`, transport stub | 🟡 types + tests |
| `crates/akurai-control` | `akurai-control` | Control plane: enrollment, IPAM, peer map, ACL, audit, heartbeat; HTTP listener seam | 🟡 skeleton |
| `crates/akurai-node` | `akurai-node` | Node daemon: TUN (`akurai0`), route apply, peer-map watch, gateway modes; `up`/`down`/`status`/`gateway` dispatch | 🟡 skeleton |
| `crates/akurai-relay` | `akurai-relay` | Ciphertext-only forward loop (relay sees no payload keys) | 🟡 skeleton |
| `crates/akurai-admin` | `akurai-admin` | Admin CLI: `preauth`/`routes`/`ingress`/`devices`/`acl` | 🟡 skeleton |
| `crates/akurai-dns` | `akurai-dns` | Internal MagicDNS: `*.oli.akurai` → overlay IP; resolver stub | 🟡 skeleton |

### `crates/akurai-common` files

| File | Responsibility | Status |
|------|----------------|--------|
| `src/lib.rs` | crate root + re-exports; `#![forbid(unsafe_code)]` | ✅ |
| `src/ids.rs` | `NodeId` (16-byte hex), `MachineKey` (opaque placeholder, redacted Debug, NO crypto) | ✅ |
| `src/overlay.rs` | constants (`TUN_INTERFACE`, `OVERLAY_MTU`, IPv4/IPv6 nets + prefix lens) + `OverlayIpv4`/`OverlayIpv6` allocation + membership | ✅ |
| `src/cidr.rs` | `Cidr` (addr + prefix) with correct v4/v6 mask membership | ✅ |
| `src/policy.rs` | `Tag`, `Principal`, `GatewayMode`, `Route`, `AclRule`, `Decision`, fail-closed `Policy::evaluate` | ✅ |
| `src/node.rs` | `Endpoint`, `NodeDescriptor` (the peer-map shape; no private keys) | ✅ |
| `src/transport.rs` | `Session`/`TransportError` **stubs** — cryptography-free, returns `NotImplemented` | ✅ stub |

### `crates/akurai-control` files

| File | Responsibility |
|------|----------------|
| `src/main.rs` | arg dispatch (`serve`/`version`/`help`) |
| `src/enrollment.rs` · `ipam.rs` · `peermap.rs` · `acl.rs` · `audit.rs` · `heartbeat.rs` | subsystem stubs (each exposes `status()`) |
| `src/listener.rs` | HTTP listener seam (`serve()` + `ControlError`); **not implemented** — needs the transport decision |

### `crates/akurai-node` files

| File | Responsibility |
|------|----------------|
| `src/main.rs` | `up`/`down`/`status`/`gateway` dispatch from `std::env::args` |
| `src/error.rs` | `NodeError` (`NotImplemented`/`Usage`) |
| `src/tun.rs` | TUN device stub (docs the `akurai0`/ioctl approach) |
| `src/route.rs` | `overlay_defaults()` (real) + `apply()` stub |
| `src/peermap.rs` | peer-map watch stub |
| `src/gateway.rs` | `gateway enable --subnet/--exit` parsing |

### `crates/akurai-admin` files

| File | Responsibility |
|------|----------------|
| `src/main.rs` | subcommand dispatch |
| `src/error.rs` | `AdminError` |
| `src/preauth.rs` · `routes.rs` · `ingress.rs` · `devices.rs` · `acl.rs` | per-subcommand parse + usage (routes validates CIDR via `akurai-common`) |

### `crates/akurai-relay` / `crates/akurai-dns` files

| File | Responsibility |
|------|----------------|
| `relay/src/main.rs` + `forward.rs` | dispatch + ciphertext forward-loop stub |
| `dns/src/main.rs` + `resolver.rs` | dispatch + `*.oli.akurai` resolver stub (`ZONE`, `resolve()`, `serve()`) |

## Directory layout

```
AkurAI-VPN/
├── AGENTS.md            ← this file (the index)
├── ISA.md              ← ideal state (problem, vision, MVP0→4 criteria)
├── CHANGELOG.md        ← Keep-a-Changelog; deploy.sh cuts releases
├── VERSION             ← starts 0.0.1; deploy.sh bumps lockstep
├── deploy.sh           ← gate → bump → changelog → tag → push → publish EC2
├── Cargo.toml          ← workspace root (zero-dep principle in the header)
├── crates/             ← one subsystem per crate, small files
├── docs/               ← architecture, networking, gateway-mode, threat-model,
│                          protocol (UNRESOLVED DECISION), deployment
├── systemd/            ← akurai-{control,relay,node}.service templates
└── tests/netns/        ← Linux netns e2e test plan
```

## Testing & release

- **Unit:** inline `#[cfg(test)]` per module (overlay allocation, CIDR
  membership, fail-closed policy, descriptor shape, stubs).
- **E2E:** Linux network namespaces — see `tests/netns/README.md` (not
  implemented in 0.0.1; needs the data plane).
- **Gates (must be clean before release):**
  ```sh
  cargo build --workspace
  cargo test  --workspace
  cargo fmt --all -- --check
  cargo clippy --all-targets -- -D warnings
  ```
- **Release:** `./deploy.sh [patch|minor|major]` runs the gate, bumps `VERSION`
  + the workspace version, cuts `CHANGELOG.md`, tags `vX.Y.Z`, pushes, then
  publishes the control plane to EC2 (`akurai-ec2`). `./deploy.sh ec2`
  re-publishes only.

## MVP ladder (build order)

0. **Planning & threat model** — _this scaffold._
1. **Single-hub internal VPN** — enrollment + static peer map + `akurai0` +
   node→hub tunnel + hub routing + ACL.
2. **Gateway routes** — subnet advertisements + approval + push; exit opt-in; DNS.
3. **Direct peer mesh** — endpoint discovery + direct paths + relay fallback +
   path health + roaming.
4. **Public ingress** — HTTPS ingress on `vpn.olibuijr.com` + TLS automation +
   identity-aware access.

**Gate before MVP 1:** resolve the transport/crypto decision in
`docs/protocol.md`.
