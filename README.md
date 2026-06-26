# AkurAI VPN

A secure, **one-touch mesh VPN** — a private encrypted overlay network with
internal mesh networking, explicit gateway modes, and a control plane at
`vpn.olibuijr.com`. Built pure-Rust with **zero runtime dependencies**, the same
principle as [AkurAI-Framework](https://github.com/olibuijr/AkurAI-Framework).
Not WireGuard-compatible by design — better tailored than a clone.

## The vision

```sh
curl -fsSL https://vpn.olibuijr.com/install.sh | sh
akurai-node up
```

Two commands and a device joins your private network: it gets a stable overlay
IP and an internal DNS name (`laptop.oli.akurai`) and can reach your other
devices, subject to access-control policy. Any device can optionally become a
**subnet gateway** (reach a LAN behind it), an **exit gateway** (full-tunnel),
or a **public ingress** (expose a service) — always with explicit admin approval.

## Overlay at a glance

| | |
|-|-|
| IPv4 | `100.88.0.0/16` |
| IPv6 | `fd88:akurai::/48` (mnemonic; real prefix `fd88::/48`) |
| MTU | `1280` |
| Interface | `akurai0` |

## Crates

| Crate | Binary | Role |
|-------|--------|------|
| `akurai-common` | _(lib)_ | Shared pure-std types: identities, overlay addressing, CIDR, policy, node descriptor. |
| `akurai-control` | `akurai-control` | Control plane (`vpn.olibuijr.com`): enrollment, IP allocation, peer map, ACL, audit, heartbeat. |
| `akurai-node` | `akurai-node` | Node daemon: `akurai0` TUN, routes, peer-map watch, gateway modes. |
| `akurai-relay` | `akurai-relay` | Ciphertext-only packet relay fallback. |
| `akurai-admin` | `akurai-admin` | Admin CLI: pre-auth, routes, ingress, devices, ACL. |
| `akurai-dns` | `akurai-dns` | Internal MagicDNS (`*.oli.akurai` → overlay IP). |

See [`docs/architecture.md`](docs/architecture.md) for the full design, and the
rest of [`docs/`](docs/) for networking, gateway modes, the threat model, the
protocol, and deployment.

## Status — `0.0.1` scaffold

This is a **skeleton, not a working VPN**. Types, module layout, CLI surfaces,
and the documented decisions are in place; the data plane (TUN, transport,
routing) is a set of clearly-marked stubs that return explicit "not implemented
in 0.0.1" errors.

> ⚠️ **No cryptography is implemented, by design.** The transport/crypto choice
> is an **unresolved decision** — vetted crypto crates (the plan's guidance) vs.
> the zero-dependency principle — documented in
> [`docs/protocol.md`](docs/protocol.md) and left for Ólafur to decide. 0.0.1
> provides **no** security properties.

## Build

```sh
cargo build --workspace
cargo test  --workspace
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

## Deploy

`./deploy.sh [patch|minor|major]` gates (fmt + clippy + tests), bumps the
version, cuts the changelog, tags + pushes, then publishes the control plane to
EC2 via the `akurai-ec2` ops CLI. `./deploy.sh ec2` re-publishes without a
version bump. See [`docs/deployment-vpn.olibuijr.com.md`](docs/deployment-vpn.olibuijr.com.md).

## License

MIT © Ólafur Búi Ólafsson
