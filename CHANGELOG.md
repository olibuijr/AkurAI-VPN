# Changelog

All notable changes to this project are documented here. Format: Keep a Changelog; SemVer.

## [Unreleased]

## [0.3.5] - 2026-07-01

- Skip loopback direct endpoint candidates


## [0.3.4] - 2026-07-01

- LAN-local direct path candidates


### Added
- LAN-local direct path candidates: running nodes now heartbeat their bound UDP
  endpoint, `/api/peermap` surfaces fresh peer endpoints, and the node probes
  those candidates before falling back to the relay.

### Fixed
- Same-LAN peers can upgrade to the local UDP path instead of keeping encrypted
  overlay traffic on the central relay path.

## [0.3.3] - 2026-06-29

### Added
- node-token revoke/rotate (dashboard + POST /api/endpoints/:id/rotate-token)

### Changed
- HANDOFF — persistent session store (v0.3.2) + Android token client done



## [0.3.2] - 2026-06-29

### Added
- persistent + expiring session store (logins survive restarts)

### Changed
- HANDOFF v0.3.1 — self-healing nodes + durable node auth tokens



## [0.3.1] - 2026-06-29

### Fixed
- accept node token on /api/endpoints; heartbeat tolerates token-backfilled id



## [0.3.0] - 2026-06-29

### Added
- durable per-node auth token (cookie bootstraps, token takes over)
- self-healing — recv survives errors, 30s peer-map refresh hot-swap
- control-plane heartbeat — running nodes report ONLINE
- ACL enforcement in the data path (fail-closed policy)
- MVP4 public ingress — TCP proxy from a public port to an internal overlay service
- IPv6 overlay data path (fd88::/48)

### Fixed
- heartbeat uses JSON body + X-CSRF-Token header

### Changed
- ACL + MVP4 ingress + IPv6 done; Android client in progress
- v0.2.0 — MVP1-3 + MagicDNS + gateways + multi-arch; honest MVP4/ACL/IPv6 roadmap



## [0.2.0] - 2026-06-29

### Added
- MVP2 exit gateway (full-tunnel) with hard safety guard
- MVP3 direct peer-to-peer mesh with relay fallback
- MagicDNS — resolve <peer>.akurai to overlay IP
- one-touch systemd tunnel daemon + network.conf + DNS relay resolve
- MagicDNS resolver + DNS wire codec for *.akurai names
- MVP2 subnet gateway — advertise + route_to + forwarding

### Fixed
- MagicDNS netns test uses per-netns resolv.conf, never touches host DNS

### Changed
- architecture, protocol, networking for the data plane
- record v0.1.0 working mesh data plane + ufw gotcha + MVP2-4 roadmap



## [0.1.0] - 2026-06-29

### Added
- working encrypted overlay mesh (akurai-sys TUN + node pump + relay)
- peer map + heartbeat endpoints for mesh data plane

### Changed
- remove stale akurai-common transport stub (decision resolved → akurai-transport)
- sync lockfile for v0.0.9
- record v0.0.9 overlay IPAM milestone + next data-plane fork



## [0.0.9] - 2026-06-28

### Added
- per-node overlay IP allocation, backfill, and surfacing

### Changed
- sync lockfile for v0.0.8



## [0.0.8] - 2026-06-28

- Require per-user VPN node networks


## [0.0.7] - 2026-06-28

- Add host-only node install defaults


## [0.0.6] - 2026-06-28

- Harden VPN control sessions and validation


## [0.0.5] - 2026-06-27

### Added
- real JWT verification via IDP introspect endpoint



## [0.0.4] - 2026-06-27

### Added
- add AkurAI IDP OIDC login, session management, and VPN endpoint CRUD (v0.0.3)



## [0.0.3] - 2026-06-27

### Added
- AkurAI IDP OIDC Authorization Code Flow login (`/login`, `/auth/callback`, `/auth/logout`)
- In-memory session store with `akurai_session` cookie (HttpOnly, Secure, SameSite=Lax, 24h TTL)
- VPN endpoint management: HTML dashboard (`/dashboard`), REST API (`GET/POST /api/endpoints`), delete (`POST /api/endpoints/:id/delete`, `DELETE /api/endpoints/:id`)
- JSON endpoint persistence to `$AKURAI_DATA_DIR/vpn-endpoints.json` with atomic rename write
- Auth state modules: `auth`, `vpn_endpoint`, `state` (zero external crates, std-only)
- CSRF protection for OIDC callback via server-side pending-state nonce set
- OIDC state nonce rotation (capped at 512 pending entries)

### Notes
- **OIDC env vars required** for login: `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI` (and optionally `OIDC_ISSUER_URL`, defaults to `https://auth.olibuijr.com`)
- **JWT signature not verified** — blocked on crypto crate decision (see Cargo.toml UNRESOLVED DECISION); token exchange itself authenticates the claims for the MVP
- Token exchange uses `curl` subprocess to reach IDP HTTPS endpoint from std-only Rust

## [0.0.2] - 2026-06-27

### Added
- implement minimal std-only HTTP listener for akurai-control serve
- scaffold pure-Rust zero-dep AkurAI VPN workspace (v0.0.1)

### Fixed
- override vpn control deploy exec
- move vpn control deploy port to 8104

### Changed
- add deploy conduct comments
- migrate to akurai-notes MCP; CLAUDE.md->@AGENTS.md; AGENTS.md->pointer
- initial commit

