# AkurAI VPN — Networking (overlay, packet flow, tests)

## Overlay addressing

The overlay is a layer-3 network reached through a TUN interface. The parameters are
fixed in `akurai-common/src/overlay.rs`:

| Parameter | Value | Constant |
|-----------|-------|----------|
| TUN interface | `akurai0` | `TUN_INTERFACE` |
| IPv4 overlay | `100.88.0.0/16` | `OVERLAY_IPV4_NET` + `OVERLAY_IPV4_PREFIX_LEN` |
| IPv6 overlay | `fd88::/48` (mnemonic `fd88:akurai::/48`) | `OVERLAY_IPV6_NET` + `OVERLAY_IPV6_PREFIX_LEN` |
| MTU | `1280` | `OVERLAY_MTU` |

`100.88.0.0/16` sits in the `100.64.0.0/10` CGNAT range — deliberately outside normal
RFC 1918 LAN ranges, so the overlay does not collide with home/office subnets. The MTU
is a conservative 1280 (the IPv6 minimum) to leave headroom for the relay frame +
crypto envelope without path-MTU discovery in the MVP. The IPv6 prefix is a real
RFC 4193 ULA (`fd88::/48`); `akurai` is a non-hex mnemonic kept in prose only.

`OverlayIpv4::from_index(n)` maps host index `n` to `100.88.0.0 + n` (index 0 is the
network address; `MAX_INDEX = 65535`). `OverlayIpv4::contains(addr)` tests
`octets[0] == 100 && octets[1] == 88`.

### IP allocation (control plane)

`akurai-control/src/ipam.rs` hands each enrolled node a stable, globally-unique
`100.88.0.N/32`:

- Reserved indices: `0` = network address, `1` = control plane
  (`CONTROL_PLANE_INDEX`). Node indices start at `FIRST_NODE_INDEX = 2`.
- `allocate()` returns the **lowest free** index ≥ 2; indices freed by node deletion are
  reused.
- `choose_for_enrollment(supplied, used)` honors a caller-supplied index only if it is a
  valid, free node index; otherwise it allocates the lowest free one.
- `assign_missing()` is the startup **backfill** — assigns IPs to nodes enrolled before
  allocation existed; idempotent. The address is stored as a `100.88.0.N/32` entry in
  the node's `allowed_ips`, so no schema change was needed.

The node's overlay IP is served to it via `/api/peermap` (peers) and read back from
`/api/endpoints` by the installer, which passes it to `akurai-node up --overlay-ip`.

### Interface bring-up (node) — overlay-only route, NEVER default

`akurai-node`'s `tunnel::run` opens `akurai0` via the one `ioctl` in `akurai-sys`, then
brings the interface up with safe `ip` commands (`std::process::Command`):

```text
ip addr add <overlay_ip>/32 dev akurai0
ip link set akurai0 mtu 1280
ip link set akurai0 up
ip route add 100.88.0.0/16 dev akurai0      # overlay-scoped route ONLY
```

It adds **no default route** — `0.0.0.0/0` is never installed. The host's existing
internet path (e.g. `wlan0`) is inviolable. This is the host-only product default:
only enrolled overlay peers are reachable. Subnet gateways (`--advertise`) and exit
gateways (`--exit-node`) are implemented, but they are strictly opt-in and never
enabled by the default installer.

## Packet flow

```text
 local app
   │  writes IPv4 packet to dest 100.88.0.3
   ▼
 akurai0 TUN (akurai-sys: /dev/net/tun, IFF_TUN | IFF_NO_PI, raw IPv4, no PI header)
   │
   ▼  tun_pump (akurai-node/src/tunnel.rs)
   ├─ require IPv4 (len ≥ 20, version nibble == 4); else drop
   ├─ dest = packet bytes [16..20]
   ├─ peer = peers.get(dest)           ── unknown dest → DROP (fail-closed)
   ├─ if session established:  ct = session.encrypt(packet)
   │                           send Frame{Data, src=self, dest, ct}
   │                           to confirmed direct path, else relay
   └─ else (first contact):    noise::initiate → send Frame{HandshakeInit,…}
                               to direct candidate first + relay fallback
                               drop this packet (TCP/ICMP retransmits later)
   │
   ▼  UDP socket (bound once; `send_to` relay or direct peer endpoint)
   ▼
 akurai-relay (forward.rs): decode envelope → learn src endpoint →
                            forward datagram to dest overlay IP's learned UDP endpoint
                            (unknown dest → DROP). Never decrypts; holds no keys.
                            On handshakes, send PeerAddr hints to both ends.
   │
   ▼  UDP at peer
   ▼  udp_pump (peer's akurai-node/src/tunnel.rs)
   ├─ HandshakeInit → noise::respond; accept only if recovered initiator static key
   │                  matches the peer-table entry for src; insert session; reply
   │                  Frame{HandshakeResp,…}
   ├─ HandshakeResp → noise::finalize the pending handshake → session established
   ├─ Data          → session.decrypt(payload) → write inner IPv4 packet to akurai0
   ├─ PeerAddr      → remember/probe candidate endpoint for a direct path
   └─ Keepalive     → direct-path confirmation handled before dispatch;
                      relay keepalives otherwise only teach the relay
   │
   ▼
 akurai0 TUN → local app on the peer
```

The two pumps (`tun_pump` on the main thread, `udp_pump` on a second thread) share a
per-peer `PeerState` (`session`, `pending`, `direct`, `candidate`) under a `Mutex`. A
third thread sends keepalives to the relay and to direct candidates/paths. The node
binds `0.0.0.0:0`; while running it reports the bound UDP port plus the local source
address used to reach the relay in `/api/heartbeat`. `/api/peermap` returns that fresh
endpoint to same-user peers, which lets two devices on the same LAN probe each other
directly instead of keeping traffic on the central relay path. End to end, the relay
only ever forwards ciphertext.

### Node sources of the peer table (`akurai-node/src/peers.rs`)

- Static file `config/peers`: one
  `<overlay_ip> <pubkey_b64> [name] [advertised] [tags] [endpoint]` per line; blank
  lines and `#` comments ignored; unparseable lines skipped (used for tests and offline
  bring-up).
- Control plane `GET /api/peermap` via `curl` with the saved cookie jar
  (`--control <url>`); pure-`std` has no TLS client, and the node already shells `ip`,
  so `curl` is consistent. JSON is parsed by a hand-rolled, dependency-free reader.
  Peer-map entries include an optional `endpoint` direct-path candidate.
- Fail-closed: an entry that does not parse is skipped; a packet to a destination not in
  the table is dropped.

## netns test topology

`tests/netns/e2e.sh` is the end-to-end proof. It stands up a relay and two nodes in
isolated Linux network namespaces — **the host stack is never touched** (`wlan0` is
structurally safe) — and pings node B from node A over the overlay, asserting the
underlay carries only ciphertext.

Underlay topology:

```text
  ns-relay 10.0.1.1  <--veth(vrA/vaR)-->  10.0.1.2  ns-a   (overlay 100.88.0.2)
  ns-relay 10.0.2.1  <--veth(vrB/vbR)-->  10.0.2.2  ns-b   (overlay 100.88.0.3)
```

The relay namespace (`akv-relay`) bridges the two node namespaces (`akv-a`, `akv-b`) at
the underlay; the relay listens on `RELAY_PORT=51820`. Each node reaches the relay by
its underlay IP (`10.0.1.1` / `10.0.2.1`).

What the script does:

1. Generate two node identities (`akurai-node install --home …`), read their
   `identity.pub`.
2. Write each node a static peer map naming the other (`100.88.0.3 <B_pub> nodeb`, etc.).
3. Build the namespaces + veth underlay.
4. Start the relay (`akurai-relay serve`) in `akv-relay`.
5. `tcpdump` the relay→B link to capture forwarded underlay traffic.
6. Start both nodes (`akurai-node tunnel --overlay-ip … --relay 10.0.x.1:51820 --peers …`).
7. **`OVERLAY_PING`** — `ping -c 4 100.88.0.3` from `akv-a`; must succeed.
8. **`CIPHERTEXT_CHECK`** — the inner ICMP payload (`abcdefghijklmnop`) must NOT appear
   in cleartext in the capture; the relay only ever sees AkurAI frames.
9. **`FAILCLOSED_CHECK`** — a ping to an un-mapped overlay IP (`100.88.0.9`) must fail
   (no peer/route → dropped).

### Running the tests

```bash
# Unit tests for every crate (frame, noise, session, ipam, peermap, relay, …):
cargo test

# Build the binaries the e2e script needs:
cargo build -p akurai-node -p akurai-relay

# End-to-end overlay proof (needs root for netns + TUN; touches no host interface):
sudo tests/netns/e2e.sh

# Direct path proof on one LAN:
sudo tests/netns/direct.sh

# Symmetric NAT proof: direct path does not form, relay fallback still works:
sudo tests/netns/symmetric.sh
```

A clean run prints `OVERLAY_PING: PASS`, `CIPHERTEXT_CHECK: PASS`, and
`FAILCLOSED_CHECK: PASS`, and exits 0.

## Future work

- **Advanced path scoring / ICE-style NAT traversal** — LAN/cone-NAT direct paths and
  symmetric-NAT relay fallback exist; richer candidate scoring remains future work.
- **Admin-managed route approvals** — the runtime can advertise subnets and opt into
  exit nodes, but the admin CLI/UI approval workflow is still skeleton-level.
- **Packaged desktop clients** — macOS utun and Windows Wintun are runtime-verified in
  CI; signed installers remain future work.
- **Ingress hardening** — the TCP ingress proxy exists; TLS automation and
  identity-aware browser access policy are still future work.
