# AkurAI VPN — Gateway Modes

Gateway modes are **first-class and explicit**. A node never gains a capability
implicitly; every advertisement requires admin approval at the control plane,
and an unapproved advertisement is rejected and audited (fail-closed — see
`threat-model.md`).

Modes are modelled in `akurai-common::policy::GatewayMode`:
`InternalMesh`, `Subnet`, `Exit`, `Ingress`.

## Internal mesh (default)

Devices reach other approved overlay devices by overlay IP or internal DNS.
Routes installed on every node:

```text
100.88.0.0/16 dev akurai0
fd88::/48     dev akurai0
```

## Subnet gateway

A node advertises a LAN/private subnet behind it.

```sh
akurai-node  gateway enable --subnet 192.168.1.0/24
akurai-admin routes approve home-router 192.168.1.0/24
```

Client route after approval:

```text
192.168.1.0/24 via home-router over akurai0
```

## Exit gateway

A node advertises default routes. **A node must never become an exit gateway
without explicit admin approval.**

```sh
akurai-node  gateway enable --exit
akurai-admin routes approve vps 0.0.0.0/0
akurai-admin routes approve vps ::/0
```

Clients opt in explicitly:

```sh
akurai-node exit use vps
akurai-node exit off
```

## Public ingress gateway (MVP 4)

`vpn.olibuijr.com` forwards selected public domains/ports to an internal node.

```sh
akurai-admin ingress create dashboard.vpn.olibuijr.com --to nas.oli.akurai:8080 --tls auto
akurai-admin ingress create ssh-vps --listen 2222 --to vps.oli.akurai:22
```

Ingress enforces ACLs and should use identity-aware auth for HTTP services.

## Approval is fail-closed

| Event | Result |
|-------|--------|
| Unknown node | no traffic |
| Unknown route | no install |
| Unapproved gateway advertisement | reject + audit |
| Expired node certificate/session | no peer map |
| Missing ACL | deny |

## Status

0.0.1 — `akurai-node gateway …` parses the command surface and reports intent;
`akurai-admin routes/ingress …` parse and validate arguments. No advertisement,
approval, or route push is implemented yet.
