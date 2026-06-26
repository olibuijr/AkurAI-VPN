# AkurAI VPN — Protocol

> The wire protocol and its cryptography are **not implemented** in 0.0.1.
> The transport/crypto modules (`akurai-common::transport`, the node TUN/peer
> stubs, the relay forward loop, the control listener) are deliberate
> placeholders that return explicit "not implemented" errors. This document
> records the intended shape and the one decision that gates everything else.

---

## 🚨 UNRESOLVED DECISION — transport & cryptography (Ólafur to decide)

**The single biggest open question, and it must be resolved before any data
plane is written.**

The planning doc is explicit on two points that are in **direct tension**:

1. **Use vetted, mature cryptography — do not invent primitives.** The plan
   names concrete crates: `quinn` + `rustls` (QUIC + TLS identity), or `snow`
   (Noise-over-UDP); `ed25519-dalek` or `ring` for identity signing;
   `rand_core` / the OS RNG for key generation.
2. **AkurAI is built pure-Rust with ZERO runtime dependencies** — the shipped
   binaries link no third-party crates, only `std` (the same principle as
   AkurAI-Framework).

You cannot have both. `std` has no cryptography, no QUIC, and no production
TLS, and **writing our own crypto is explicitly forbidden** (it is the fastest
way to ship a catastrophic vulnerability). So the project must choose:

### Option A — Stay strictly std-only (zero dependencies)

Implement transport and the security envelope from scratch over `std` UDP/TCP.

- **Pro:** preserves the zero-dependency principle byte-for-byte; one
  self-contained binary; nothing to audit downstream.
- **Con:** this means **writing cryptography ourselves** — handshakes, AEAD, key
  agreement, a CSPRNG. This is a **severe security risk** and contradicts the
  plan's own "do not invent primitives" rule. Not recommended for anything
  carrying real traffic.

### Option B — Allow one (or a few) audited crypto/transport crates

Relax the zero-dependency rule **only** for vetted cryptography and transport —
e.g. adopt `quinn` + `rustls` (QUIC-first) or `snow` (Noise), plus an
identity/signing crate and the OS RNG.

- **Pro:** real, reviewed security; matches the plan's explicit guidance; far
  less risk; faster to a trustworthy MVP.
- **Con:** breaks the "shipped binary links no third-party crates" principle;
  adds a supply chain to vet and track; the binary is no longer std-only.

### What is NOT on the table

Inventing cryptographic primitives. If Option A is chosen, it must reuse a
genuinely vetted construction, not a home-grown cipher or handshake — and even
then, a from-scratch std-only crypto stack is a security risk that should be
weighed very carefully.

### Decision

**Left for Ólafur.** This scaffold does not pick. The transport/crypto modules
stay stubs until the call is made; whichever option wins, the existing seams
(`Session`, the TUN/route/peermap stubs, the relay forward loop, the control
listener) are where it lands.

---

## Intended protocol shape (once transport is chosen)

The recommendation in the plan is **QUIC-first, hub-routed**: easier reliable
streams, NAT rebinding, keepalives, and TLS identity; optimise raw packet
transport later once behaviour is proven.

### Identity & enrollment

1. Node generates a local machine key (type TBD per the decision above).
2. Node requests a short pairing code.
3. CLI prints `https://vpn.olibuijr.com/pair/ABCD-EFGH`.
4. User approves in the browser or with `akurai-admin`.
5. Control plane assigns overlay IP, DNS name, ACL tags, route policy.
6. Node starts `akurai0` and applies routes.
7. Node begins the peer-map watch stream.

Admin pre-auth equivalent:

```sh
akurai-admin preauth create --user oli --ttl 1h
akurai-node  up --auth-key akp_...
```

### Sessions & the relay

- Control plane distributes signed node descriptors / certificates.
- Nodes verify a peer descriptor before establishing a session.
- Direct encrypted path when healthy; **relay fallback** via `vpn.olibuijr.com`
  otherwise. **The relay only ever sees ciphertext** and holds no payload keys.

## Other decisions deferred to Ólafur

From the plan's "Open Design Questions":

1. QUIC-first vs Noise-over-UDP _(folded into the decision above)_.
2. Hub-routed only first, or attempt direct mesh immediately. _(Plan recommends
   hub-routed first.)_
3. Persistent state: pure-Rust `redb` vs SQLite — note both are dependencies, so
   this is also gated by the zero-dependency stance.
4. `vpn.olibuijr.com` on the existing mail EC2 box vs a dedicated VPN VM.
5. Public ingress in v1 or v2. _(Plan: MVP 4.)_
6. First client OSes: Linux only, or Linux + Android/Termux.
