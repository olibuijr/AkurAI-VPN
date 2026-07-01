# AkurAI VPN — Architecture (data plane)

AkurAI VPN is a private, encrypted L3 overlay network. The data plane uses direct
peer paths with relay fallback: peers prefer a confirmed direct UDP address
(including same-LAN private addresses advertised through heartbeat), and use the
central relay only until a direct path is proven or when direct UDP cannot work. The
relay never holds payload keys — it moves end-to-end ciphertext. This document
describes what is actually built and deployed; remaining management and packaging
gaps are explicitly marked as future work.

The whole shipped data plane is **pure Rust, `std`-only, zero runtime dependencies**.
The single `unsafe` in the codebase is one `ioctl` to create the TUN device
(`akurai-sys`); everything else — packet I/O, sockets, interface setup, crypto — is
safe `std`. Data-plane cryptography is hand-rolled in `akurai-crypto` against RFC test
vectors (decision resolved 2026-06-27: keep the zero-dependency identity rather than
link rustls/quinn/snow/ed25519; the hand-rolled-crypto risk is accepted deliberately).

Workspace version: `0.3.5`, deployed live on 2026-07-01. The
first working encrypted overlay mesh landed in the `0.1.0` changelog entry
(2026-06-29).

## Components (crates)

| Crate | Role | Key contents |
|-------|------|--------------|
| `akurai-common` | Wire/value codecs, no crypto | `frame` (relay envelope), `overlay` (`100.88.0.0/16`, `akurai0`, MTU 1280, IP allocation arithmetic), `b64` (RFC 4648 Base64) |
| `akurai-crypto` | Zero-dep crypto primitives | `x25519` (RFC 7748), `chacha20poly1305` (RFC 8439), `blake2s` (RFC 7693), `hkdf`; each verified against official RFC vectors in-crate |
| `akurai-transport` | Secure channel | `noise` (WireGuard-style `Noise_IK` handshake), `session` (counter-nonce data packets + 64-entry replay window), `Keypair`/`TransportKeys` |
| `akurai-sys` | The OS seam | `raw` (the only `unsafe` — one `ioctl(TUNSETIFF)` via a direct `syscall`), `tun` (`create` → `/dev/net/tun` handle, `IFF_TUN | IFF_NO_PI`) |
| `akurai-node` | Node daemon | `identity` (persistent X25519 static keypair), `peers` (overlay-IP-indexed peer table + direct endpoint candidates), `acl` (optional tag policy), `tunnel` (the TUN↔UDP pump with direct path + relay fallback), `main` (CLI: `install`/`up`/`down`/`tunnel`/`service-install`/`status`/`path`/`version`) |
| `akurai-relay` | Ciphertext-only fallback hub | `forward` (learn src endpoint, forward by dest overlay IP, send `PeerAddr` hints during handshakes, drop unknown; holds no keys, links no crypto crate) |
| `akurai-control` | Control plane (HTTP) | `ipam` (overlay IP allocation), `peermap` (`/api/peermap` with fresh endpoint candidates), `heartbeat` (`/api/heartbeat`, liveness TTL + node UDP endpoint), `listener` (auth + CSRF + endpoint CRUD) |
| `akurai-admin` | Admin CLI | preauth/routes/ingress/devices/ACL command surface; currently a skeleton, not the live management path |
| `akurai-dns` | Internal/MagicDNS | zero-dep DNS codec/server for `*.akurai`; also used by the node tunnel path |
| `akurai-ingress` | Public ingress | pure-std TCP proxy from a public port to an internal overlay service |

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

akurai-dns / akurai-ingress (optional service binaries used for MagicDNS and public
                             TCP ingress around the same overlay)
```

- `akurai-common` is shared, crypto-free value code: it codes the relay `Frame`, owns
  the overlay constants/arithmetic, and provides Base64.
- `akurai-control` is a control-plane HTTP server, out of the packet path. It assigns
  overlay IPs and serves the peer map; it carries no data-plane payloads.
- The **relay** sees only the `Frame` envelope. The **node** is the only place that
  holds session keys and does encryption/decryption.

## Direct Path With Relay Fallback

```text
 node A (100.88.0.2)              direct UDP               node B (100.88.0.3)
   app → akurai0 TUN                 forward.rs                 akurai0 TUN → app
        │                          (no keys held)                     ▲
        │  UDP: AkurAI Frame                                          │
        │  {Data, src=.2, dest=.3, ciphertext}                        │
        ├─────────────────────────────────────────────────────────────┘
        │
        └──────── relay fallback until direct is confirmed ──────────►
```

1. Each node binds one UDP socket and sends `Keepalive` frames to the relay so the
   relay can forward fallback traffic.
2. The node also heartbeats its current local UDP endpoint to the control plane.
   `/api/peermap` returns fresh same-user peers with overlay IP, public key,
   liveness, and the best direct endpoint candidate.
3. To reach a peer, the node runs a `Noise_IK` handshake **end to end**. It tries a
   direct candidate first when one is known and keeps relay fallback available. The
   relay additionally sends `PeerAddr` hints during handshakes with the addresses it
   observes.
4. A direct address is only promoted after a valid frame arrives from a configured
   peer. Once confirmed, `Data` frames go peer-to-peer; if no direct path forms, the
   relay forwards ciphertext by destination overlay IP.
5. **Fail-closed** throughout: a packet to an unknown destination (node side: not in
   the peer table; relay side: endpoint not yet learned) is dropped, never buffered.

## What is deployed live

- **Control plane:** `vpn.olibuijr.com` (control listener on port **8104**) — OIDC login
  via the AkurAI IDP, per-user VPN networks, endpoint CRUD, overlay IP allocation,
  `/api/peermap`, `/api/heartbeat`. Validated against the live deployment.
- **Relay:** runs on the AkurAI EC2 box, **UDP/51820** (`RELAY_PORT`, default 51820).
- **Public site / installer:** `akurai-vpn.olibuijr.com` serves the landing page and
  `install.sh`; the node binary is published at
  `/downloads/akurai-node-linux-x86_64.bin`.
- **Node:** installs to `~/.akurai-vpn` by default; the installer starts a systemd
  tunnel service when sudo is available. Default routing stays host-only/overlay-only:
  subnet and exit gateways exist, but only when explicitly configured.

## MVP1 → MVP4 ladder

| Wave | Scope | Status |
|------|-------|--------|
| **MVP0** | Planning, threat model, protocol decision (Noise-over-UDP, hand-rolled), DNS/deploy plan | **DONE** |
| **MVP1** | Single-hub internal VPN: enrollment + static/served peer map, TUN creation, end-to-end-encrypted node↔node tunnel via the relay, overlay IP allocation, netns e2e proof | **DONE** |
| **MVP2** | Gateway routes: subnet advertisement, route push to clients, exit-gateway opt-in, MagicDNS names | **DONE** for opt-in runtime primitives; admin approval UX remains future work |
| **MVP3** | Direct peer mesh: endpoint discovery, direct UDP attempts, NAT traversal, relay fallback, path-health scoring, roaming | **DONE** for same-LAN/cone-NAT direct paths + symmetric-NAT relay fallback; advanced scoring/ICE remains future work |
| **MVP4** | Public ingress: public TCP proxy to internal overlay services, TLS automation, identity-aware access | **DONE** for pure-Rust TCP ingress; TLS automation and identity-aware ingress policy remain future work |

### Future work

- **Advanced path scoring / ICE-style NAT traversal** — current direct paths use
  heartbeat endpoint candidates plus relay `PeerAddr` hints, with symmetric-NAT
  relay fallback; richer scoring and candidate sets are future work.
- **Management UX for approvals** — `akurai-admin` has the command surfaces for
  pre-auth keys, route approval, ingress, devices, and ACLs, but those subcommands are
  still skeletons. Runtime gateway/ACL/ingress primitives are tested separately.
- **Packaged desktop clients** — Linux and Android are published; macOS utun and
  Windows Wintun paths are runtime-verified in CI, but signed installers are still
  future work.
- **TLS automation / identity-aware public ingress** — `akurai-ingress` is a TCP proxy;
  HTTPS certificate automation and browser-facing access policy are not built yet.
- **WireGuard hardening on the handshake** — no pre-shared key, no MAC1/MAC2/cookie, no
  timestamp anti-replay on handshake initiation (a later phase). See `protocol.md`.
