# AkurAI VPN — Architecture (data plane)

AkurAI VPN is a private, encrypted L3 overlay network. In MVP1 it is **hub-routed**:
every node sends all overlay traffic to a single relay, which forwards each datagram
to the destination's last-known UDP endpoint. The relay never holds payload keys — it
moves end-to-end ciphertext. This document describes what is actually built and
deployed; aspirational features are explicitly marked **NOT YET BUILT**.

The whole shipped data plane is **pure Rust, `std`-only, zero runtime dependencies**.
The single `unsafe` in the codebase is one `ioctl` to create the TUN device
(`akurai-sys`); everything else — packet I/O, sockets, interface setup, crypto — is
safe `std`. Data-plane cryptography is hand-rolled in `akurai-crypto` against RFC test
vectors (decision resolved 2026-06-27: keep the zero-dependency identity rather than
link rustls/quinn/snow/ed25519; the hand-rolled-crypto risk is accepted deliberately).

Workspace version: `0.1.0`. The first working encrypted overlay mesh landed in the
`0.1.0` changelog entry (2026-06-29).

## Components (crates)

| Crate | Role | Key contents |
|-------|------|--------------|
| `akurai-common` | Wire/value codecs, no crypto | `frame` (relay envelope), `overlay` (`100.88.0.0/16`, `akurai0`, MTU 1280, IP allocation arithmetic), `b64` (RFC 4648 Base64) |
| `akurai-crypto` | Zero-dep crypto primitives | `x25519` (RFC 7748), `chacha20poly1305` (RFC 8439), `blake2s` (RFC 7693), `hkdf`; each verified against official RFC vectors in-crate |
| `akurai-transport` | Secure channel | `noise` (WireGuard-style `Noise_IK` handshake), `session` (counter-nonce data packets + 64-entry replay window), `Keypair`/`TransportKeys` |
| `akurai-sys` | The OS seam | `raw` (the only `unsafe` — one `ioctl(TUNSETIFF)` via a direct `syscall`), `tun` (`create` → `/dev/net/tun` handle, `IFF_TUN | IFF_NO_PI`) |
| `akurai-node` | Node daemon | `identity` (persistent X25519 static keypair), `peers` (overlay-IP-indexed peer table), `tunnel` (the TUN↔UDP pump), `main` (CLI: `install`/`up`/`down`/`tunnel`/`status`/`path`/`version`) |
| `akurai-relay` | Ciphertext-only hub | `forward` (learn src endpoint, forward by dest overlay IP, drop unknown; holds no keys, links no crypto crate) |
| `akurai-control` | Control plane (HTTP) | `ipam` (overlay IP allocation), `peermap` (`/api/peermap`), `heartbeat` (`/api/heartbeat`, liveness TTL), `listener` (auth + CSRF + endpoint CRUD) |
| `akurai-admin` | Admin CLI | users/devices/ACLs/routes (early; data-plane policy NOT YET wired) |
| `akurai-dns` | Internal/MagicDNS | placeholder — **NOT YET BUILT** (folded into control plane later) |

## Layering

```text
akurai-crypto  (X25519 / ChaCha20-Poly1305 / BLAKE2s / HKDF, zero-dep primitives)
      │
      ▼
akurai-transport  (Noise_IK handshake + authenticated data-packet Session)
      │
      ├──────────────► akurai-node ◄── akurai-sys (TUN device, the one ioctl)
      │                    │
      │                    └── akurai-common (Frame envelope, overlay addressing, b64)
      │
      └──────────────► akurai-relay (reads only the Frame envelope; no crypto)

akurai-control  (separate process: IPAM + peer map + heartbeat over HTTP; uses
                 akurai-common overlay arithmetic, never touches the data plane)
```

- `akurai-common` is shared, crypto-free value code: it codes the relay `Frame`, owns
  the overlay constants/arithmetic, and provides Base64.
- `akurai-control` is a control-plane HTTP server, out of the packet path. It assigns
  overlay IPs and serves the peer map; it carries no data-plane payloads.
- The **relay** sees only the `Frame` envelope. The **node** is the only place that
  holds session keys and does encryption/decryption.

## The hub-routed MVP1 model

```text
 node A (100.88.0.2)                relay (hub)                node B (100.88.0.3)
   app → akurai0 TUN                 forward.rs                 akurai0 TUN → app
        │                          (no keys held)                     ▲
        │  UDP: AkurAI Frame                                          │
        │  {Data, src=.2, dest=.3, ciphertext}                        │
        └───────────────────────────►  learn src endpoint  ──────────┘
                                       forward by dest IP
```

1. Each node connects a UDP socket to the relay and periodically sends a `Keepalive`
   frame (every 20 s). The relay learns "overlay IP X is reachable at UDP address Y".
2. To reach a peer, the node runs a `Noise_IK` handshake **end to end** (the handshake
   messages travel as relay frames the relay forwards blindly), then encrypts each
   inner IPv4 packet into a `Data` frame.
3. The relay forwards each frame to the destination overlay IP's last-known endpoint.
   It never decrypts; for `Data` frames the payload is ciphertext it cannot read.
4. **Fail-closed** throughout: a packet to an unknown destination (node side: not in
   the peer table; relay side: endpoint not yet learned) is dropped, never buffered.

There is no direct node-to-node path and no NAT traversal in MVP1 — all traffic
transits the hub.

## What is deployed live

- **Control plane:** `vpn.olibuijr.com` (control listener on port **8104**) — OIDC login
  via the AkurAI IDP, per-user VPN networks, endpoint CRUD, overlay IP allocation,
  `/api/peermap`, `/api/heartbeat`. Validated against the live deployment.
- **Relay:** runs on the AkurAI EC2 box, **UDP/51820** (`RELAY_PORT`, default 51820).
- **Public site / installer:** `akurai-vpn.olibuijr.com` serves the landing page and
  `install.sh`; the node binary is published at
  `/downloads/akurai-node-linux-x86_64.bin`.
- **Node:** installs to `~/.akurai-vpn` by default; host-only membership, no routes
  beyond the overlay, never a default route.

## MVP1 → MVP4 ladder

| Wave | Scope | Status |
|------|-------|--------|
| **MVP0** | Planning, threat model, protocol decision (Noise-over-UDP, hand-rolled), DNS/deploy plan | **DONE** |
| **MVP1** | Single-hub internal VPN: enrollment + static/served peer map, TUN creation, end-to-end-encrypted node↔node tunnel via the relay, overlay IP allocation, netns e2e proof | **DONE** |
| **MVP2** | Gateway routes: subnet advertisement, admin route approval, route push to clients, exit-gateway opt-in, basic DNS names | NOT YET BUILT |
| **MVP3** | Direct peer mesh: endpoint discovery, direct UDP attempts, NAT traversal, relay fallback, path-health scoring, roaming | NOT YET BUILT |
| **MVP4** | Public ingress: HTTPS ingress on the control host to internal services, TLS automation, identity-aware access | NOT YET BUILT |

### Explicitly not yet built

- **Direct mesh / NAT traversal** — MVP3. Every packet currently transits the relay.
- **Subnet / exit / gateway routes** — MVP2. The node installs an overlay-only route
  and *never* a default route.
- **MagicDNS / internal DNS** (`akurai-dns`) — placeholder crate.
- **ACL enforcement in the data path** — the node authenticates peers by static key and
  fail-closes on unknown destinations, but there is no tag/policy ACL check on the
  packet path yet. The richer policy model (tags, `can_advertise`, allow rules) lives
  only in planning/admin scaffolding.
- **WireGuard hardening on the handshake** — no pre-shared key, no MAC1/MAC2/cookie, no
  timestamp anti-replay on handshake initiation (a later phase). See `protocol.md`.
