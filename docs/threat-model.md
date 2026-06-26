# AkurAI VPN — Threat Model

> MVP 0 deliverable. This is a scaffold-stage threat model: it states the
> security goals, the trust boundaries, and the fail-closed policy that the
> design must uphold. It is **not** a claim that 0.0.1 is secure — 0.0.1 has no
> data plane and no cryptography (see `protocol.md`).

## Assets

- Overlay traffic between enrolled devices (confidentiality + integrity).
- Node identities and their long-term keys.
- The control plane's policy, peer map, and audit log.
- The enrollment / pairing channel.

## Trust boundaries

| Boundary | Trust |
|----------|-------|
| Enrolled node ↔ enrolled node | Mutually authenticated; traffic end-to-end encrypted. |
| Node ↔ control plane (`vpn.olibuijr.com`) | Node trusts the control plane for policy and addressing; control plane authenticates the node. |
| Node ↔ relay | **Relay sees only ciphertext.** It is trusted to forward, not to read — it holds no payload keys. |
| Anything un-enrolled | Untrusted. Fail-closed: no identity ⇒ no traffic. |

## Adversaries

- **On-path network attacker** — can observe/modify/drop packets between nodes
  and the hub. Mitigated by end-to-end encryption + authentication (transport
  TBD) and by the relay never holding payload keys.
- **Malicious/compromised relay** — sees ciphertext only; cannot decrypt or
  inject authenticated traffic.
- **Compromised node** — limited by ACL policy and route approval; cannot
  advertise routes or become a gateway without admin approval, and every such
  attempt is audited.
- **Rogue enrollment** — mitigated by the pairing-approval step (browser or
  admin CLI) and pre-auth keys with TTLs.

## Fail-closed policy (must hold)

The policy model is deny-by-default. `akurai-common::policy::Policy::evaluate`
returns `Allow` only when a rule explicitly permits the flow.

| Condition | Outcome |
|-----------|---------|
| Unknown node | no traffic |
| Unknown route | no install |
| Unapproved gateway advertisement | reject + audit |
| Expired node certificate / session | no peer map |
| Missing ACL | deny |

## Cryptography posture (UNRESOLVED)

The plan mandates vetted crypto (QUIC+TLS via `quinn`/`rustls`, or Noise via
`snow`; identity via `ed25519-dalek`/`ring`; OS RNG for key generation) and
explicitly forbids inventing primitives. This collides with the
zero-runtime-dependency principle. **No cryptography is implemented in this
repository**, and none will be added until the decision in `protocol.md` is
made. Treat 0.0.1 as providing **no** security properties.

## Out of scope (for now)

- NAT-traversal-specific attacks (no direct mesh until MVP 3).
- Public ingress / identity-aware HTTP auth (MVP 4).
- Supply-chain hardening of any future crypto dependency (revisit once chosen).
