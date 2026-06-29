# AkurAI-VPN Handoff

Date: 2026-06-28

This document is the current working handoff for the AkurAI-VPN effort. It captures the live state of the system, what was changed, what remains, and the constraints another agent must preserve while continuing.

## Update — 2026-06-29 (v0.2.0): MVP1–3 + MagicDNS + gateways + multi-arch — a working Tailscale alternative

Built on top of the v0.1.0 mesh, all pure-Rust zero-dep, each **verified in network namespaces** (host stack never touched) and committed:

- **MVP3 — direct peer-to-peer mesh** (`FrameKind::PeerAddr`): handshakes go via the relay, which hints each end the other's observed UDP address; nodes probe (NAT hole-punch) and **upgrade off the relay to a direct path**, with relay fallback. Per-peer `PeerState{session,pending,direct,candidate}`. Proof: `tests/netns/direct.sh`.
- **MVP2 — subnet gateway**: `--advertise <CIDR>` + peers-file 4th field; peers route the subnet over the overlay to the gateway, which `ip_forward`s to the real LAN. Proof: `tests/netns/subnet.sh`.
- **MVP2 — exit gateway (full-tunnel)**: `--exit-node <peer>` opt-in routes `0.0.0.0/0` via **`/1` routes that never delete the real default** (tunnel close = auto-restore); `--advertise 0.0.0.0/0` enables MASQUERADE. A `0.0.0.0/0` advertisement is **never** auto-installed (hard safety guard). Proof: `tests/netns/exit.sh`.
- **MagicDNS**: node serves `<overlay_ip>:53` resolving `<peer>.akurai` (`akurai-dns` lib). Proof: `e2e.sh` MagicDNS check.
- **One-touch daemon**: `akurai-node service-install` (systemd, `CAP_NET_ADMIN`, boot-start) + `network.conf`-driven `tunnel`; installer auto-runs it with sudo. FIX: relay resolved as `host:port` via DNS.
- **Multi-arch**: `akurai-node` cross-compiles to **aarch64** with just `rust-lld` (zero-dep payoff). Published `akurai-node-linux-aarch64.bin`.

### Live (v0.2.0) — REDEPLOYED
Control plane **v0.2.0** (vpn.olibuijr.com), relay **v0.2.0** (EC2 systemd, restarted — emits PeerAddr so direct-path works in prod), node binary **0.2.0** (x86_64 + aarch64) + installer published.

### Regression — `sudo tests/netns/{e2e,subnet,direct,exit}.sh` → 7/7 PASS
OVERLAY_PING · CIPHERTEXT · MAGICDNS · FAILCLOSED · SUBNET_GATEWAY · DIRECT_PATH · EXIT_GATEWAY.

### Gotchas (carry forward)
1. **netns resolv.conf trap** (FIXED): never write `/etc/resolv.conf` inside `ip netns exec` unless `/etc/netns/<ns>/resolv.conf` exists first — it clobbers the HOST's resolv.conf.
2. **EC2 relay port**: host `ufw` INPUT-policy-DROP — the AWS SG rule alone is NOT enough; also `sudo ufw allow 51820/udp`.
3. **Host safety**: all multi-node verification in netns; never bring a tunnel up in the host namespace.

### Now ALSO done (this session, verified in netns, committed)
- **MVP4 — public ingress**: new `akurai-ingress` crate (`serve --map <port>:<overlay_ip>:<target_port>`) — pure-std TCP proxy from a public port to an internal overlay service. Proof: `tests/netns/ingress.sh`.
- **Fine-grained ACL enforcement** in the data path: peer tags (peers-file 5th field / peer map), a local `config/acl` policy, `--my-tags`, enforced fail-closed in `tun_pump` (denied flow dropped). `akurai-node/src/acl.rs` + `akurai-common::policy`. Proof: `tests/netns/acl.sh` (ALLOW + DENY).
- **IPv6 overlay data path** (`fd88::/48`): node assigns `fd88::N` + routes it; `tun_pump` parses IPv6 + `peers.route_to_ip`. Proof: `e2e.sh` IPV6_CHECK (`ping -6 fd88::3`).
- **Android client**: `~/Projects/AkurAI-VPN-Android` — Rust JNI backend (`rust/`, fd-based pump cdylib) + Kotlin `VpnService` app (`app/`), Tailscale-style. (Build/deploy in progress.)

**Full regression now 6 tests / 11 checks: `sudo tests/netns/{e2e,subnet,direct,exit,acl,ingress}.sh` → ALL PASS.**

### Remaining toward 100% "complete" (honest roadmap)
- **Control-plane endpoint distribution** for robust symmetric-NAT direct paths (relay PeerAddr handles cone NAT today).
- **Production hardening**: session rekey/expiry, durable node auth token (peer-map fetch uses the OIDC cookie), key rotation.
- **Android app polish**: device-test on hardware, identity registration with the control plane, multi-arch APK, Play-store packaging.

---

## Update — 2026-06-29 (v0.1.0): WORKING ENCRYPTED MESH DATA PLANE (MVP1) — live

The VPN now actually tunnels traffic. A node brings up `akurai0`, and one enrolled device can `ping` another over the `100.88.0.0/16` overlay, carried as end-to-end ChaCha20-Poly1305 ciphertext, hub-routed through the relay (which holds no keys). **Proven end-to-end** in Linux netns locally AND against the live deployed relay on EC2.

### What was built (all pure-Rust, zero external deps)
- **`akurai-sys`** (new crate): creates the `akurai0` TUN via a single isolated `ioctl(TUNSETIFF)` raw syscall — the only unsafe in the data plane. All other I/O is safe std.
- **`akurai-common`**: relay `frame` codec (envelope `[AC01][ver][type][dst v4][src v4][len][payload]`) + `b64`.
- **`akurai-node`**: X25519 identity (gen/persist 0600, idempotent); `tunnel` daemon = TUN + UDP + Noise_IK sessions + TUN↔UDP pump; peer table (static file OR curl-fetched `/api/peermap`); brings up the overlay with a `100.88.0.0/16`-ONLY route (never a default route).
- **`akurai-relay`**: ciphertext-only forward hub — learns each node's UDP endpoint from frame sources, forwards by destination overlay IP, decrypts nothing.
- **`akurai-control`**: `GET /api/peermap` + `POST /api/heartbeat` (authenticated, user-scoped, TTL liveness); node records now carry the real X25519 pubkey.
- **`tests/netns/e2e.sh`**: the end-to-end proof (encrypted ping + ciphertext-on-underlay + fail-closed-drop).

### Live state
- **Control plane** v0.1.0 — vpn.olibuijr.com (`/api/peermap`, `/api/heartbeat` live, validate 11/11).
- **Relay** v0.1.0 — EC2 systemd `akurai-vpn-relay.service`, UDP `0.0.0.0:51820`. **GOTCHA (fixed): the host runs `ufw` with INPUT policy DROP — the AWS security-group rule alone was NOT enough; the relay was unreachable until `sudo ufw allow 51820/udp` on the box. Both the SG and ufw must allow the relay port.**
- **Installer + node binary 0.1.0** — published to akurai-vpn.olibuijr.com; installer registers the real identity pubkey, writes relay config, and prints the `sudo akurai-node tunnel …` start command.

### Safety held
All multi-node verification ran in network namespaces; the host (`midget`) default route on `wlan0` was never touched, no `akurai0` ever appeared in the host namespace. The overlay TUN installs ONLY `100.88.0.0/16`, never `0.0.0.0/0`.

### Remaining roadmap toward a "complete Tailscale alternative" (NOT yet built)
1. **MVP3 — direct peer mesh / NAT traversal** (currently hub-routed only): endpoint discovery, UDP hole-punching, path health, relay fallback.
2. **MVP2 — gateway routes**: subnet advertise + admin approval + client route push; exit-gateway opt-in (default-route — careful: this is where host-route risk lives).
3. **MagicDNS**: resolve `node.user.akurai` → overlay IP (akurai-dns is still a stub).
4. **ACL enforcement in the data path**: the fail-closed policy model exists in `akurai-common::policy` but is not yet wired into the node pump or relay.
5. **Production daemon**: a privileged systemd `akurai-node tunnel` service auto-installed by the installer (needs root/CAP_NET_ADMIN); session rekey/expiry; roaming.
6. **Multi-OS clients** (Android/Termux per the plan); IPv6 overlay data path.

ISA for this wave: `~/.claude/PAI/MEMORY/WORK/akurai-vpn-dataplane/ISA.md`.

---

## Update — 2026-06-28 (v0.0.9): overlay IP allocation shipped

The "next milestone" decision below was made and implemented: **per-node overlay IP allocation (IPAM)**. It was the only one of the three options with zero `wlan0` risk (pure control-plane bookkeeping) and is the prerequisite for any future data plane.

- Control plane (`crates/akurai-control`): real allocator in `ipam.rs` — each enrolled node gets a stable, globally-unique `100.88.0.N/32` from `100.88.0.0/16` (lowest-free index, reused on delete; indices 0/1 reserved). Allocation runs **under the state lock** (race-safe) and normalizes to exactly one overlay address per node. A startup **backfill** assigns IPs to nodes enrolled before allocation existed and persists atomically.
- Surfacing: `VpnEndpoint` JSON gained `overlay_ipv4`; the dashboard has an **Overlay IP** column; the control banner names the next free address.
- Node (`crates/akurai-node`): `up --overlay-ip <ip>` persists it locally; `status` shows `overlay : <ip>`.
- Installer (`akurai-vpn-site/frontend/install.sh`): reads the assigned IP back from `/api/endpoints` and passes it to `akurai-node up --overlay-ip`. New `0.0.9` node binary published to the site downloads.
- **LIVE & verified:** control plane v0.0.9 on vpn.olibuijr.com (`validate.sh` 11/11 PASS); the `midget` record now carries `100.88.0.2` (backfilled automatically on deploy). `wlan0` default route + connectivity unchanged before/after; no `akurai0`, no routes.

**Next milestone (the deferred fork — nothing foreclosed):** the actual data plane — direct peer-to-peer connectivity using the already-built `akurai-crypto` (zero-dep X25519/ChaCha20-Poly1305) + `akurai-transport` (Noise_IK) stack. Each node now has a real overlay address to bind to. **This is where `wlan0` risk re-enters** (TUN device, routes) — preserve the host-only safety protocol below.

> Note: the memory note saying the crypto decision is "OPEN" is **stale** — it was resolved zero-dep (see `crates/akurai-crypto`, `crates/akurai-transport`, both with passing end-to-end tests).

## Current Product Direction

The VPN is intentionally host-only by default.

- Only devices with the AkurAI-VPN node installed should be reachable.
- No subnet routing, exit routing, or gateway advertisement should happen in the default install.
- Each AkurAI user has their own private network.
- Install path defaults to `~/.akurai-vpn`.
- The node must not disturb the machine's existing internet connectivity, especially `wlan0`.

## Live State

### Control plane

- Public health: `https://vpn.olibuijr.com/api/health`
- Current live version: `0.0.8`
- Validation script passes against the live deployment.

### Public site

- Public health: `https://akurai-vpn.olibuijr.com/api/health`
- Installer: `https://akurai-vpn.olibuijr.com/install.sh`
- Downloaded node artifact is now published as:
  - `https://akurai-vpn.olibuijr.com/downloads/akurai-node-linux-x86_64.bin`

### Installed node on this machine

- Host: `midget`
- Installed home: `/home/olafurbui/.akurai-vpn`
- Installed binary: `/home/olafurbui/.akurai-vpn/bin/akurai-node`
- Local state file: `/home/olafurbui/.akurai-vpn/state/node.state`
- Current local state:
  - `state=up`
  - `mode=host-only`
  - `routing=disabled`

The control plane currently shows the node record as:

- name: `midget`
- id: `5d838b5344d14603`
- public key: `VGwyx1S7OcPIW6pnH+GPIUFCn92qW3cKbHKuYhiXtlg=`
- added by: `olibuijr@olibuijr.com`
- endpoint: empty
- allowed IPs: empty

That means the node is registered, but no overlay endpoint address has been assigned or configured yet in the control plane record.

## Safety Constraint

Do not break the machine's existing network access while working on this.

- `wlan0` connectivity was verified during install/deploy work.
- The default route remained on `wlan0`.
- The node implementation is host-only and does not create routes or TUN-based gateway behavior.

Before any future networking change:

1. Verify the default route still points to `wlan0`.
2. Verify external connectivity with a simple HTTP check.
3. Re-check after the change before and after restarting services.

## What Was Changed

### Node daemon

In `AkurAI-VPN/crates/akurai-node/src/main.rs`:

- Added explicit commands for:
  - `install`
  - `up`
  - `down`
  - `status`
  - `path`
  - `version`
  - `help`
- Default install location is now `~/.akurai-vpn`.
- `up` only enables host-only membership.
- `status` reports host-only mode and routing disabled.
- `install` writes local config/state and copies the binary into the user home.

Related cleanup:

- `gateway.rs` and `route.rs` were removed.
- `tun.rs` and `peermap.rs` were reduced to host-only notices.

### Control plane

In `AkurAI-VPN/crates/akurai-control/src/listener.rs`:

- Added CSRF support for endpoint mutation routes.
- Endpoint listing and deletion are scoped to the authenticated user.
- Dashboard and API continue to require authentication.

In `AkurAI-VPN/systemd/akurai-control.service`:

- Removed the checked-in OIDC secret.
- The service now expects OIDC values from an environment file.

In `AkurAI-VPN/scripts/validate.sh`:

- Validation now works both locally and over SSH.
- It targets `/api/health`.
- It handles the intentional no-code callback error page.

### Public site

In `akurai-vpn-site/frontend/install.sh`:

- Installer downloads the node binary.
- Installer prompts for AkurAI IDP credentials.
- Installer completes IDP login, follows the continue page, and registers the node in the user's network.
- Installer finishes by running `akurai-node up --home ~/.akurai-vpn`.

In `akurai-vpn-site/frontend/index.html`:

- Landing page now explains host-only behavior.
- It states the default install path.
- It tells users that each AkurAI account gets its own network.
- It gives a simple install command and status check.

## Deployment Notes

### Control plane

The live control plane is currently healthy and passing validation.

Useful command:

```bash
cd /home/olafurbui/Projects/AkurAI-VPN
./scripts/validate.sh
```

### Site deployment caveat

The `akurai-vpn-site` tree is not a git repo in the same way as the VPN repo.
The release/deploy flow previously failed because the release engine expected `frontend/` relative to the wrong directory.

If you need to refresh the static site, do not assume the repo deploy flow is reliable without checking it first.

Observed workaround during this session:

- copy the updated frontend files directly into the deployed app tree on `akurai-mail`
- restart `akurai-vpn-site.service`

### Static download caveat

Framework-style static serving treated extensionless download URLs like HTML pages.
The node binary now needs the `.bin` suffix for a clean download.

Use:

```text
/downloads/akurai-node-linux-x86_64.bin
```

not the extensionless path.

## Install and Test Flow

The intended user-facing install flow is:

```bash
curl -fsSL https://akurai-vpn.olibuijr.com/install.sh | sh
```

The installer should:

1. Download the node binary.
2. Install it under `~/.akurai-vpn/bin/akurai-node`.
3. Prompt for AkurAI IDP credentials.
4. Register the node in the user's own VPN network.
5. Start host-only membership.

Post-install checks:

```bash
~/.akurai-vpn/bin/akurai-node status
~/.akurai-vpn/bin/akurai-node path
~/.akurai-vpn/bin/akurai-node version
```

Expected status characteristics:

- `mode: host-only`
- `routing: disabled`
- `state: up` after install

## What Another Agent Should Do Next

1. Keep the host-only default intact.
2. Preserve `wlan0` internet connectivity while making any further networking changes.
3. Decide whether the next milestone is:
   - actual per-node overlay IP allocation,
   - direct peer-to-peer connectivity,
   - or route advertisement beyond host-only mode.
4. If adding IP assignment, ensure the control-plane record stores and surfaces it clearly.
5. If touching deploy flow for `akurai-vpn-site`, verify the static artifact path and the release-engine working directory before changing code.
6. Re-run `./scripts/validate.sh` after any change to the control plane.

## References

- `AkurAI-VPN/crates/akurai-node/src/main.rs`
- `AkurAI-VPN/crates/akurai-control/src/listener.rs`
- `AkurAI-VPN/scripts/validate.sh`
- `AkurAI-VPN/systemd/akurai-control.service`
- `AkurAI-VPN/CHANGELOG.md`
- `akurai-vpn-site/frontend/install.sh`
- `akurai-vpn-site/frontend/index.html`

