# AkurAI VPN — Protocol (relay frame, handshake, data session)

This describes the on-the-wire protocol of the MVP1 data plane, taken directly from
the code. Three layers stack inside one UDP datagram:

1. the **relay frame** — the outer envelope the relay reads and forwards
   (`akurai-common/src/frame.rs`);
2. the **Noise_IK handshake** — carried in `HandshakeInit` / `HandshakeResp` frame
   payloads (`akurai-transport/src/noise.rs`);
3. the **data session packet** — carried in `Data` frame payloads as end-to-end
   ciphertext (`akurai-transport/src/session.rs`).

## 1. Relay frame envelope

Every datagram on the underlay is one `Frame`. Big-endian, **14-byte header**, then
payload. The relay reads only this envelope; it never inspects the payload.

```text
offset:  0    2    3      4          8          12     14
         +----+----+------+----------+----------+------+------------------+
         |AC01| v  | type | dest v4  | src v4   | len  | payload (len B)  |
         +----+----+------+----------+----------+------+------------------+
bytes:    2    1    1       4          4          2      len
```

| Field | Offset | Size | Value |
|-------|--------|------|-------|
| Magic | 0 | 2 | `MAGIC = [0xAC, 0x01]` ("AkurAI v1") |
| Version | 2 | 1 | `VERSION = 1` |
| Type | 3 | 1 | `FrameKind` byte (see below) |
| Dest overlay IPv4 | 4 | 4 | `dest.octets()`, big-endian; `0.0.0.0` = the relay itself |
| Src overlay IPv4 | 8 | 4 | `src.octets()`; what the relay learns the sender's endpoint as |
| Payload length | 12 | 2 | `u16` big-endian, `len ≤ MAX_PAYLOAD` |
| Payload | 14 | `len` | opaque to the relay |

Constants: `HEADER_LEN = 14`, `MAX_PAYLOAD = 2048`.

`FrameKind` type byte:

| Byte | Kind | Meaning |
|------|------|---------|
| 1 | `Keepalive` | Node→relay liveness; teaches the relay this `src` overlay IP's UDP endpoint. Payload empty. **Not forwarded.** |
| 2 | `HandshakeInit` | Noise_IK message 1 (initiator → responder), payload-opaque (96 B) |
| 3 | `HandshakeResp` | Noise_IK message 2 (responder → initiator), payload-opaque (48 B) |
| 4 | `Data` | An end-to-end-encrypted inner IPv4 packet (ciphertext to the relay) |

`Frame::encode()` lays the bytes out exactly as above. `Frame::decode()` is
**fail-closed** and never panics — it returns `None` on any of: buffer shorter than
`HEADER_LEN`, wrong magic, wrong version, unknown type byte, `len > MAX_PAYLOAD`, or a
`len` that exceeds the bytes actually present (`buf.len() < HEADER_LEN + len`).
`Frame::new()` likewise rejects a payload larger than `MAX_PAYLOAD`.

No cryptography lives in this layer — it is a pure value codec.

## 2. Noise_IK handshake

A WireGuard-style **`Noise_IK`** handshake: one round trip, mutually authenticated. The
initiator already knows the responder's static public key (the `K` token); the
responder learns and authenticates the initiator's static key from message 1 (the `I`
token). It is built on the zero-dependency `akurai-crypto` primitives — X25519,
ChaCha20-Poly1305, BLAKE2s, HKDF.

```text
  Initiator                                    Responder
  --------- msg1: e, es, s, ss  (96 B) ------->
  <-------- msg2: e, ee, se      (48 B) -------
```

Protocol labels mixed into the initial chaining key / transcript hash (changing either
breaks wire compatibility):

- `CONSTRUCTION = "Noise_IK_25519_ChaChaPoly_BLAKE2s"`
- `IDENTIFIER   = "AkurAI VPN v1 2026"`

### Symmetric state

Both peers carry a chaining key `ck` (feeds the KDF) and a transcript hash `h`
(authenticates each AEAD as associated data). They absorb the same values in the same
order and converge on identical `ck`/`h`, hence identical transport keys.

- `mix_hash(h, data) = BLAKE2s(h || data)`
- `kdf1(ck, x) = HKDF<1>(ck, x)` → next `ck`
- `kdf2(ck, x) = HKDF<2>(ck, x)` → `(next ck, AEAD key)`
- Prelude: `ck = BLAKE2s(CONSTRUCTION)`, `h = BLAKE2s(ck || IDENTIFIER)`, then
  `h = mix_hash(h, responder_static_pub)`.

Every handshake AEAD uses a single all-zero 96-bit nonce (`ZERO_NONCE`). Each AEAD key
is derived fresh by the KDF and used exactly once, so the nonce never repeats under a
given key.

### Message 1 — `initiate()` (96 bytes)

`initiate(static_kp, responder_pub, ephemeral_secret) -> (Initiator, msg1)`:

1. `e`  — `e_pub = X25519.base(ephemeral_secret)`; `ck = kdf1(ck, e_pub)`; `h = mix_hash(h, e_pub)`.
2. `es` — `es = DH(ephemeral, responder_static)`; `(ck, k) = kdf2(ck, es)`;
   `enc_static = AEAD.seal(k, ZERO_NONCE, h, static_kp.public)`; `h = mix_hash(h, enc_static)`.
3. `ss` — `ss = DH(static, responder_static)`; `(ck, k) = kdf2(ck, ss)`;
   `enc_empty = AEAD.seal(k, ZERO_NONCE, h, [])`; `h = mix_hash(h, enc_empty)`.

Wire layout: `e_pub(32) || enc_static(48) || enc_empty(16) = 96`. The carried
`Initiator` state (private) holds `ck`, `h`, the initiator static keypair, and the
ephemeral secret.

### Message 2 — `respond()` (48 bytes)

`respond(static_kp, ephemeral_secret, msg1) -> Option<(TransportKeys, msg2, init_static_pub)>`.
Rejects (`None`) if `msg1.len() != 96` or any AEAD tag fails. It replays the prelude
and the `e/es/ss` steps to decrypt and **authenticate** the initiator's static key
(`init_static_pub`), then:

1. `er_pub = X25519.base(ephemeral_secret)`; `ck = kdf1(ck, er_pub)`; `h = mix_hash(h, er_pub)`.
2. `ee = DH(resp_ephemeral, init_ephemeral)`; `ck = kdf1(ck, ee)`.
3. `se = DH(resp_ephemeral, init_static)`; `ck = kdf1(ck, se)`.
4. `(ck, k) = kdf2(ck, [])`; `enc_empty2 = AEAD.seal(k, ZERO_NONCE, h, [])`.

Wire layout: `er_pub(32) || enc_empty2(16) = 48`. Final split: `(t1, t2) = kdf2(ck, [])`;
the responder is the second party, so `TransportKeys { send: t2, recv: t1 }`. It also
returns the authenticated `init_static_pub` so the caller can match it against the peer
table.

### Finish — `finalize()`

`finalize(Initiator, msg2) -> Option<TransportKeys>`. Rejects if `msg2.len() != 48` or
the `enc_empty2` tag fails. Replays `e/ee/se`, opens `enc_empty2`, then splits the same
`(t1, t2) = kdf2(ck, [])`; the initiator is the first party, so
`TransportKeys { send: t1, recv: t2 }`.

The two peers' keys mirror: `initiator.send == responder.recv` and
`initiator.recv == responder.send`. Authentication is **implicit** — if any DH input,
static key, or ciphertext differs, a downstream AEAD tag check fails and the handshake
aborts. A single flipped byte in msg1 or msg2 is rejected (tested).

**Not yet built (handshake hardening):** no pre-shared key, no MAC1/MAC2/cookie
(DoS/anti-amplification), no handshake timestamp. These are a later phase.

## 3. Data session packet

After a handshake both sides build a `Session` from their `TransportKeys`. Each data
packet is the WireGuard data-packet construction:

```text
+----------------------+-----------------------------------------------+
| counter (8 B, BE)    | ChaCha20-Poly1305(send_key, nonce, aad=[], pt) |
+----------------------+-----------------------------------------------+
```

- **Counter:** `send_counter`, monotonic from 0, big-endian, 8 bytes. Never reused under
  a given `send_key`.
- **AEAD nonce (12 B):** four zero bytes followed by the counter little-endian —
  `nonce(counter) = [0,0,0,0] || counter.to_le_bytes()`. Unique per packet under a fixed
  key.
- **AAD:** empty.
- This ciphertext (counter prefix + AEAD output, including the 16-byte tag) is the
  payload of a `Data` relay frame.

### Anti-replay (inbound `decrypt`)

A 64-entry sliding window (`WINDOW = 64`) over `recv_max` / `recv_mask`:

1. Cheap pre-auth reject of hopelessly old counters
   (`recv_started && recv_max >= WINDOW && counter <= recv_max - WINDOW`).
2. **Verify the AEAD tag** — the counter is never trusted until the tag verifies.
3. Enforce replay and slide the window:
   - first accepted packet: set `recv_max = counter`, `recv_mask = 1`;
   - `counter > recv_max`: shift the mask up by the gap (or clear it if the gap
     `≥ WINDOW`), set the low bit, advance `recv_max`;
   - `counter ≤ recv_max`: reject if `recv_max - counter ≥ WINDOW` (too old) or the
     window bit is already set (replay); otherwise set the bit.

`decrypt` returns `None` on a bad tag, a replayed counter, a counter older than the
window, or a packet shorter than 8 bytes. In-window reordering is accepted; each packet
decrypts exactly once.

## Endpoint learning (relay)

The relay keeps `HashMap<overlay_ip, UDP_endpoint>`. For every received frame whose
`src` is not `0.0.0.0`, it records "this `src` is reachable at the UDP address the
datagram arrived from" — so a **roaming** node's mapping updates on its next keepalive
or data frame. `Keepalive` frames only teach the relay and are not forwarded. A
`Data`/handshake frame for a destination the relay has not yet learned is **dropped**
(`dropped_unknown`); the relay never buffers unbounded state. Counters tracked:
`learned`, `forwarded`, `dropped_unknown`, `malformed`.

## Fail-closed rules (summary)

- **Frame decode:** any malformed envelope → dropped (`Frame::decode` returns `None`).
- **Node, outbound:** a TUN packet whose destination overlay IP is not in the peer table
  is dropped. First contact triggers a handshake and the triggering packet is dropped
  (upper-layer TCP/ICMP retransmits once a session exists).
- **Node, inbound `HandshakeInit`:** the responder accepts only if the Noise-recovered
  initiator static key matches the peer-table entry for `frame.src`
  (`p.public_key == init_pub`); otherwise the handshake is dropped — no session, no
  reply.
- **Node, inbound `Data`:** decrypted only against an established session for `frame.src`;
  a bad tag / replay / unknown source yields nothing written to the TUN.
- **Relay:** unknown destination → dropped, never buffered. The relay holds no keys and
  cannot read `Data` payloads.
- **Control plane:** `/api/peermap` and `/api/heartbeat` require auth + CSRF and are
  scoped per user; a heartbeat for an id the caller does not own returns 404.
