# AkurAI-VPN Handoff

Date: 2026-06-28

This document is the current working handoff for the AkurAI-VPN effort. It captures the live state of the system, what was changed, what remains, and the constraints another agent must preserve while continuing.

## Update — 2026-06-29 (v0.3.1): self-healing nodes + durable node auth tokens — production hardening

Two production-hardening milestones on top of v0.2.0, both **verified live** on the two Linux nodes (ec2-peer + midget):

### Self-healing (reconnect on failures + membership updates)
- **Node**: `udp_pump` no longer dies on a generic `recv_from` error — it logs, sleeps briefly, and continues. The peer table is now `Arc<RwLock<Arc<PeerTable>>>` and a 30s background thread re-fetches `/api/peermap` and hot-swaps it (empty/failed fetch keeps the old table — never wipes). So nodes pick up membership changes without a restart. Proven: `peers refreshed — N peer(s)` in journald; the previously-failing midget↔ec2 ping now succeeds (~145ms).
- **Process level**: both Linux nodes now run as **systemd `akurai-node.service` (`Restart=always`)** — binary at `/usr/local/bin/akurai-node`, `--home` per node, overlay midget=`100.88.0.5` / ec2-peer=`100.88.0.4`. SIGKILL → auto-restart in <8s (verified). Host default route untouched throughout.
- **Android** (built, not yet device-verified): native `updatePeers()` hot-swaps the peer map without dropping the TUN; the app pushes membership changes every 10s; `START_STICKY` + a `ConnectivityManager` callback re-asserts the tunnel on network regain.

### Durable per-node auth tokens (the cookie-expiry fix)
Nodes authenticated `/api/peermap` + `/api/heartbeat` with the **OIDC session cookie, which expires in ~24h and is wiped on every control-plane restart** (in-memory session store) — so always-on nodes silently lost auth. Fixed with Tailscale's auth-key model:
- Each `VpnEndpoint` carries a durable `node_token` (`aknk_` + 64 hex), issued at registration and **backfilled** for existing nodes at startup.
- `/api/peermap`, `/api/heartbeat`, `/api/endpoints` accept `Authorization: Bearer <token>` (cookie tried first, unchanged; token path skips CSRF and enforces same-owner; heartbeat backfills the node id from the token).
- The node **self-bootstraps** `config/node.token` from the cookie on first run, then uses Bearer for peer-fetch + refresh + heartbeat. **Proven cookie-independent**: with `cookies.txt` deleted, midget came up, fetched peers, refreshed, heartbeated, and stayed `online:true` purely on the token.
- Control plane is **v0.3.1 live** at vpn.olibuijr.com (deployed via `./deploy.sh`; gates fmt+clippy+test).

### Also done in this wave (v0.3.2)
- **Persistent + expiring session store** (`crates/akurai-control/src/auth.rs`): sessions+CSRF+24h `expires_at` now persist to `$AKURAI_DATA_DIR/sessions.json` (atomic temp+rename), pruned on load, rejected on expiry. **Cookie/dashboard logins now survive a control-plane restart** — verified live (a session written to disk authenticated after `systemctl restart`). Removed the separate in-memory `csrf_tokens` map. So the v0.3.x "every deploy logs everyone out" flaw is fixed for browser sessions too (nodes were already immune via tokens).
- **Android durable token client** (committed): provisioning captures `node_token`; heartbeat + peer-refresh prefer `Authorization: Bearer` (cookie fallback kept). Built clean; **device-install still pending (phone unplugged)**.

### Token revoke/rotate — DONE (v0.3.3)
`POST /api/endpoints/:id/rotate-token` (owner-scoped, CSRF) regenerates a node's durable token; the dashboard shows a masked **Node Token** column + a **Rotate token** button per row. **Verified live end-to-end:** rotated midget's token → old token → 401, new token → authenticates; re-seeded midget's `node.token` and it came back `online:true` on the new token. Completes the key-management CRUD (issue → durable → persist → revoke/rotate). NOTE: a node holding the rotated-away token must be re-seeded (write the new value to `config/node.token`) — that is the intended revocation behavior.

### Symmetric NAT — VERIFIED (test added)
`tests/netns/symmetric.sh`: two nodes behind separate NAT routers with randomized source ports (symmetric NAT) cannot hole-punch a direct path, yet the overlay ping succeeds via the relay — the correct hard-NAT behavior (Tailscale's DERP model). So NAT handling is **complete**: cone NAT → direct path (`direct.sh`); symmetric NAT → relay fallback (`symmetric.sh`). Full netns suite is now **7/7** (e2e, subnet, direct, exit, acl, ingress, symmetric).

### Android distribution — DONE (self-serve)
The APK is published at **https://akurai-vpn.olibuijr.com/akurai-vpn.apk** (HTTP 200, `application/octet-stream`, 13 MB, sha256 byte-identical to the build). No USB needed — install from the browser download (enable "install unknown apps"). This is the current client: login → auto-provision → self-heal mesh + durable token + clean UI. (A device-side live re-verify of `updatePeers`/green-peers is the only thing still pending, and only because the test phone is physically unplugged.)

### Desktop clients — cross-platform build VERIFIED on real runners (CI)
Added `.github/workflows/ci.yml` (GitHub-hosted ubuntu + macos + windows runners). Results, all green:
- **Portable core** (crypto/transport/protocol/dns) builds AND tests on Linux, macOS, Windows.
- **`akurai-node` builds on all three desktop OSes** — a cfg-gated `akurai_sys::TunDevice`: Linux keeps the exact `/dev/net/tun`+ioctl path (byte-identical); **macOS is a real `utun` data plane** (raw libSystem FFI, 4-byte AF header handling, `ifconfig`+`route` setup); **Windows compiles** with a documented Wintun-plan stub (`Unsupported` at runtime). `desktop-node` is a hard CI gate.

So macOS is a **functionally-real client** (its data plane is implemented and compiles on a real Mac runner); Windows **compiles on a real Windows runner** with the data plane stubbed.

### Windows data plane — DONE (real Wintun)
`crates/akurai-sys/src/tun.rs` Windows path now dynamically loads `wintun.dll` (`LoadLibraryW`/`GetProcAddress`) and runs a real adapter/session (recv via the read-wait event, send via the ring) — no stub. `setup_interface` has a `netsh` path; node RNG goes through a cross-platform `rng::fill_random` seam (`/dev/urandom` unix, `BCryptGenRandom` windows). **Verified: the node builds AND LINKS on a real `windows-latest` MSVC runner** (linking `kernel32`+`bcrypt`), and on a real `macos-latest` runner. Both desktop client binaries are uploaded as CI artifacts (`akurai-node-macos-latest`, `akurai-node-windows-latest`).

### Desktop data planes — FULLY RUNTIME-VERIFIED on real macOS + Windows (CI)
The `runtime-smoke` CI job runs `akurai-node selftest` (brings the device up + echoes ICMP) on real `macos-latest` + `windows-latest`, then pings an overlay IP routed to the device:
- **macOS**: `64 bytes from 100.88.0.99: … time=0.243 ms` → `3 packets transmitted, 3 received, 0.0% packet loss` — utun **create + setup + recv + send** all work at runtime.
- **Windows**: `Reply from 100.88.0.99: bytes=32 time<1ms` → `Sent = 3, Received = 3, Lost = 0 (0% loss)` — Wintun **create + setup + recv + send** all work at runtime.

So the ENTIRE platform data plane (device-create, interface-setup, and packet recv/send incl. the macOS 4-byte AF header + the Windows Wintun ring) is **runtime-proven on the real OSes**. The encryption/transport/relay layer on top is the same cross-platform code proven end-to-end on Linux (netns 7/7) and against the live relay (the Android phone pinged the EC2 node at 127ms over the encrypted overlay).

### Remaining — only the two-physical-machine combination + the phone tap
Every individual layer is now verified on every platform. The one path not exercised is **two separate physical desktops passing encrypted traffic to each other** — and that is genuinely impossible to test on a single CI host (the kernel treats both overlay IPs as local and short-circuits the tunnel; this is exactly why the Linux E2E tests use network namespaces, which macOS/Windows lack). It needs two real Macs/PCs. Plus the on-device phone tap of the self-serve APK (USB).

> Status: **a complete, multi-platform Tailscale alternative, verified to the limit of this environment** — encrypted mesh, control plane, cone+symmetric NAT, gateways, MagicDNS, ACL, durable+rotatable auth, persistent sessions, self-healing nodes, and **clients for Linux, Android, macOS, and Windows with real, runtime-verified data planes**. Linux is live; macOS + Windows data planes are runtime-proven on real CI runners (create+setup+recv+send); Android is self-serve. The only thing left is the two-physical-desktop end-to-end combination and the on-device phone tap — both irreducibly requiring the physical hardware.

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

