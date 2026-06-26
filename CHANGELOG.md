# Changelog

All notable changes to AkurAI VPN are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries below the `## [Unreleased]` heading are maintained by hand during
development; `deploy.sh` cuts them into a versioned, dated section on release.

## [Unreleased]

### Added
- **Workspace scaffold** (pure-Rust, zero runtime dependencies) — a six-crate
  Cargo workspace for AkurAI VPN: a secure, one-touch mesh VPN overlay. Mirrors
  the AkurAI-Framework conventions (`[workspace.package]` version inheritance,
  `[profile.release]`, `rust-toolchain.toml`, `VERSION`, Keep-a-Changelog,
  `deploy.sh` release engine). The shipped binaries link no third-party crates —
  `std` only.
- **`akurai-common`** (lib, pure std) — the shared vocabulary of the overlay:
  `NodeId` (16-byte hex) and an opaque, cryptography-free `MachineKey`
  placeholder; overlay constants (`akurai0`, MTU 1280, IPv4 `100.88.0.0/16`,
  IPv6 `fd88::/48`) with `OverlayIpv4`/`OverlayIpv6` index allocation + membership;
  a `Cidr` type with correct v4/v6 mask membership; the policy model
  (`Tag`, `Principal`, `GatewayMode`, `Route`, `AclRule`, `Decision`) with a
  **fail-closed** `Policy::evaluate`; the `NodeDescriptor` peer-map shape; and a
  deliberate transport stub. 19 unit tests cover overlay allocation, CIDR
  membership, and fail-closed policy.
- **`akurai-control`** (bin) — control-plane skeleton: command dispatch plus
  enrollment / IPAM / peer-map / ACL / audit / heartbeat subsystem stubs and an
  HTTP listener seam. The listener is intentionally unimplemented (no std HTTP
  server, and the transport decision is open).
- **`akurai-node`** (bin) — node daemon skeleton: `up`/`down`/`status`/`gateway`
  dispatch parsed from `std::env::args` (no `clap`); TUN (`akurai0`), route, and
  peer-map-watch stubs; `route::overlay_defaults()` builds the real default
  overlay routes.
- **`akurai-relay`** (bin) — relay skeleton documenting the "relay sees only
  ciphertext" invariant, with a stubbed forward loop.
- **`akurai-admin`** (bin) — admin CLI skeleton: `preauth`/`routes`/`ingress`/
  `devices`/`acl` subcommand dispatch with usage; `routes approve` validates its
  CIDR argument through `akurai-common`.
- **`akurai-dns`** (bin) — internal MagicDNS skeleton for the `*.oli.akurai`
  zone, with a stub resolver.
- **Docs** (`docs/`) — `architecture.md`, `networking.md`, `gateway-mode.md`,
  `threat-model.md`, `protocol.md`, and `deployment-vpn.olibuijr.com.md`,
  porting the design per topic (overlay ranges, MVP0→4 ladder, fail-closed
  policy model, enrollment UX).
- **UNRESOLVED DECISION — transport & cryptography** (`docs/protocol.md`) — a
  prominent section recording the conflict between the plan's mandate to use
  vetted crypto crates (`quinn`/`rustls`/`snow`/`ed25519`) and this project's
  zero-runtime-dependency principle. Both options (std-only-from-scratch =
  security risk vs. allow one audited crypto crate) are documented; the choice is
  explicitly left for Ólafur. **No cryptography is implemented anywhere.**
- **systemd templates** (`systemd/`) — `akurai-control.service`,
  `akurai-relay.service`, `akurai-node.service` (state `/var/lib/akurai-vpn`,
  config `/etc/akurai-vpn`; the node unit carries `CAP_NET_ADMIN` + `/dev/net/tun`).
- **netns e2e test plan** (`tests/netns/README.md`) — the four-namespace
  (`ns-control`/`ns-node-a`/`ns-node-b`/`ns-gateway`) Linux network-namespace
  plan and the full test-requirements checklist.
- **`deploy.sh`** — release engine adapted from AkurAI-Framework for
  `olibuijr/AkurAI-VPN`: gate (fmt/clippy/test) → bump `VERSION` + workspace
  version → cut `CHANGELOG.md` → commit/tag/push → publish the control plane to
  EC2 via `akurai-ec2` behind nginx on `vpn.olibuijr.com:8096` (TLS skips
  gracefully while DNS is unresolved). Includes an `ec2`-only re-publish mode.
- **AGENTS.md / ISA.md** — the crate map + constitutional principles, and the
  ideal-state artifact (problem, vision, MVP0→4 criteria, open decisions).
