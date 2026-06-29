# Changelog

All notable changes to this project are documented here. Format: Keep a Changelog; SemVer.

## [Unreleased]

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


