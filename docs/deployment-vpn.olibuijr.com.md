# AkurAI VPN — Deploying `vpn.olibuijr.com`

> Deployment plan for the control plane. **`vpn.olibuijr.com` did not resolve as
> of 2026-06-25** — DNS setup is still required, so TLS issuance will defer until
> the record exists. The only reachable VM today is `mail.olibuijr.com` (the
> AkurAI Mail EC2 instance, `us-east-1`).

## One-touch install (target UX)

```sh
curl -fsSL https://vpn.olibuijr.com/install.sh | sh
akurai-node up
```

## DNS

1. Create a DNS record for `vpn.olibuijr.com` (managed at 1984.is via the
   `1984dns` CLI, like the rest of `olibuijr.com`).
2. Decide whether it points at the existing `mail.olibuijr.com` EC2 box or a new
   dedicated VPN VM _(open question — see `protocol.md`)_.

## Security-group ports

| Port | Purpose |
|------|---------|
| `443/tcp` | control API, pairing UI, relay fallback, public ingress |
| UDP (TBD) | peer transport (exact port set with the transport decision) |
| UDP (optional) | STUN-like hole-punching, if not folded into peer transport |

## systemd units

Templates live in `systemd/`. Install to `/etc/systemd/system/` (or as
`--user` units), then `systemctl enable --now`:

- `akurai-control.service`
- `akurai-relay.service`
- `akurai-node.service`

State and config paths (per the plan):

| Path | Contents |
|------|----------|
| `/var/lib/akurai-vpn` | server state (peer map, allocations, audit log) |
| `/etc/akurai-vpn` | configuration |

## Deploy via `./deploy.sh`

`deploy.sh` gates (fmt + clippy + tests), bumps `VERSION` and the workspace
version in lockstep, cuts `CHANGELOG.md`, commits/tags/pushes, then publishes the
control plane to EC2 through the reusable `akurai-ec2` ops CLI:

```sh
akurai-ec2 deploy-binary akurai-vpn-control <musl-bin> 8096
akurai-ec2 nginx-proxy   vpn.olibuijr.com 8096
akurai-ec2 tls           vpn.olibuijr.com    # skips gracefully if DNS unresolved
```

`./deploy.sh ec2` re-publishes without a version bump. The control-plane binary
is built as a static `x86_64-unknown-linux-musl` target.

> Note: until `vpn.olibuijr.com` resolves, the `tls` step is expected to defer —
> run `akurai-ec2 tls vpn.olibuijr.com` again once the DNS record propagates.

## Status

0.0.1 — the control-plane HTTP listener is a stub (no server until the transport
decision lands), so a deploy ships a binary that prints status and exits. The
pipeline, units, and paths are in place for when the data plane exists.
