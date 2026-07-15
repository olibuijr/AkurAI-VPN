# AGENTS.md — AkurAI VPN

Documentation has been migrated to the **akurai-notes** MCP.

- **Canonical note:** `AkurAI-VPN — Docs` (note ID 30), notebook **AkurAI-VPN** (ID 6)
- **Secrets:** akurai-passvault (none found at migration time)

## How to retrieve

```
search_notes("AkurAI-VPN")
get_note(30)
```

Covers: README · crate map · constitutional principles · MVP ladder · CHANGELOG · ISA · architecture · networking · gateway modes · threat model · resolved zero-dependency protocol decision · deployment · netns test plan.

## Live development and validation

- Canonical working clone: Titan, `/home/olafurbui/Projects/AkurAI-VPN`.
- Titan is `100.88.0.9`; midget is `100.88.0.7`; TV is `100.88.0.8`.
- The live nodes currently use relay-only established data delivery. Direct candidates are still learned and may carry handshakes, but duplicating identical ciphertext over direct and relay paths is forbidden because the second copy trips anti-replay handling.
- Handshakes expire and retry after three seconds. Authenticated fresh initiations replace stale sessions, and undecryptable data triggers handshake recovery after a peer restart.
- Required zero-warning/error gates before deployment:
  `cargo fmt --check`;
  `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets -- -D warnings`;
  `RUSTFLAGS="-D warnings" cargo test --workspace`.
- Deploy identical release binaries to all nodes and verify their SHA-256 hashes before restarting services.

