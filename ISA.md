---
project: AkurAI-VPN
task: 0.0.1 scaffold — pure-Rust mesh VPN skeleton
effort: E3
phase: complete
progress: scaffold
mode: build
started: 2026-06-26
updated: 2026-06-26
---

# ISA — AkurAI VPN scaffold

> The broader map stays in `AGENTS.md`; this ISA records the ideal state of the
> product and the 0.0.1 scaffold increment.

## Problem

Reaching your own devices across networks is either insecure (port-forwarding,
exposed services) or fiddly (hand-rolled WireGuard, certificate juggling, manual
IP and route management). There is no one-touch, auditable, self-hosted overlay
tailored to Ólafur's stack — and existing Rust meshes are either WireGuard-bound
or carry licenses/architectures that don't fit.

## Vision

A device joins the private network with two commands
(`curl … | sh` then `akurai-node up`), gets a stable overlay IP and an internal
DNS name, and reaches every other approved device by either — subject to
fail-closed access-control policy. Any device can, with explicit admin approval,
become a subnet gateway, an exit gateway, or a public ingress. A control plane at
`vpn.olibuijr.com` owns identity, addressing, and policy; a relay carries traffic
when a direct path fails and never sees plaintext. All of it pure-Rust with zero
runtime dependencies, like AkurAI-Framework.

## Out of Scope

This increment is the **0.0.1 scaffold** — crate layout, shared types, CLI
surfaces, docs, systemd templates, and the netns test plan. It is **not** a
working VPN: no TUN device, no transport, no routing, no cryptography. The
transport/crypto choice is deliberately deferred (see Decisions).

## Principles

- Zero runtime dependencies; shipped binaries are `std`-only.
- Do not invent or write cryptography.
- Fail-closed: deny by default, explicit authority for routes and gateways.
- Small scoped files; docs + changelog ship with each change.

## Constraints

- Pure `std`; workspace crates only; no `tokio`/`axum`/`quinn`/`rustls`/`snow`/
  `serde`/`clap`.
- No `todo!()`/`unimplemented!()` that could panic; stubs return explicit
  "not implemented in 0.0.1" errors or print usage.
- Must pass `cargo build`/`test`/`fmt --check`/`clippy -D warnings`.

## Goal

Ship a compiling, gate-clean six-crate workspace that expresses the whole
AkurAI VPN design as types, module seams, and documented decisions, so MVP 1 can
be built straight onto it once the transport decision is made.

## Criteria

- [x] ISC-1: Workspace builds; `akurai-common` is pure-std with real unit tests
      (overlay IP allocation from index, CIDR membership, fail-closed policy).
- [x] ISC-2: Five binaries dispatch their command surfaces and never panic
      (explicit "not implemented" errors / usage, no `todo!()`).
- [x] ISC-3: Transport/crypto is a clearly-marked stub; NO cryptography anywhere.
- [x] ISC-4: `docs/protocol.md` carries a prominent UNRESOLVED DECISION section
      (vetted crypto vs zero-dep), explicitly left for Ólafur — not picked.
- [x] ISC-5: All four gates clean (`build`, `test`, `fmt --check`,
      `clippy --all-targets -D warnings`).
- [x] ISC-6: Docs, systemd templates, and the netns test plan capture the
      overlay ranges, MVP ladder, policy model, and enrollment UX.
- [x] ISC-7: `deploy.sh` adapts the framework release engine for
      `olibuijr/AkurAI-VPN` → `vpn.olibuijr.com` (TLS skips if DNS unresolved).

## MVP ladder (north-star criteria)

- **MVP 0** — Planning + threat model + protocol decision + DNS/deploy plan.
  _(This scaffold delivers the artifacts; the decision itself is still open.)_
- **MVP 1** — Single-hub internal VPN: enrollment, static peer map, `akurai0`
  TUN, encrypted node→hub tunnel, hub routing, ACL.
- **MVP 2** — Gateway routes: subnet advertisements + approval + push, exit
  opt-in, basic DNS names.
- **MVP 3** — Direct peer mesh: endpoint discovery, direct paths, relay
  fallback, path health, roaming.
- **MVP 4** — Public ingress: HTTPS on `vpn.olibuijr.com`, TLS automation,
  identity-aware access.

## Decisions

- **D-1 (OPEN — Ólafur): transport & cryptography.** Vetted crypto crates
  (`quinn`/`rustls`/`snow`/`ed25519`, the plan's guidance) vs the
  zero-dependency principle. Writing our own crypto is off the table. Documented
  in full in `docs/protocol.md`; gates MVP 1.
- **D-2: hub-routed first.** MVP 1 tunnels nodes to `vpn.olibuijr.com`; direct
  mesh is MVP 3. Avoids getting stuck in NAT traversal before the core behaviour.
- **D-3: IPv6 mnemonic.** The plan's `fd88:akurai::/48` is non-hex; the code
  uses the real ULA prefix `fd88::/48` and keeps the mnemonic in prose.

## Verification

`cargo build --workspace`, `cargo test --workspace` (19 unit tests),
`cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings` — all
clean. Binaries smoke-run without panics.
