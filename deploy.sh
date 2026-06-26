#!/usr/bin/env bash
# deploy.sh — AkurAI VPN release engine.
#
#   ./deploy.sh [patch|minor|major]   release: gate → bump → changelog → tag →
#                                      push → publish control plane (default: patch)
#   ./deploy.sh ec2                    publish the control plane only (no bump)
#
# A release runs the quality gate, bumps VERSION + the workspace version in
# lockstep, cuts CHANGELOG.md, tags + pushes, then publishes the control-plane
# binary to the AkurAI AWS box behind nginx + TLS via the reusable `akurai-ec2`
# ops CLI at https://vpn.olibuijr.com.
set -euo pipefail

REPO="olibuijr/AkurAI-VPN"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

say() { printf '\033[1;34m▸ %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# ── Live publish ────────────────────────────────────────────────────────────
# Build the static musl control-plane binary and ship it to the AkurAI AWS box
# behind nginx + TLS, via the reusable `akurai-ec2` ops CLI. Idempotent. Shared
# by `./deploy.sh ec2` and the tail of every release. Missing `akurai-ec2` is a
# warning, not a failure — a release that is already tagged and pushed must not
# be undone by an absent ops CLI.
#
# NOTE: vpn.olibuijr.com may not resolve yet (DNS setup pending), so the TLS step
# is expected to defer gracefully until the record propagates.
ec2_publish() {
  if ! command -v akurai-ec2 >/dev/null; then
    say "akurai-ec2 not on PATH — skipping live publish (run './deploy.sh ec2' later)"
    return 0
  fi
  local DOMAIN="vpn.olibuijr.com" PORT=8096 NAME="akurai-vpn-control"
  local MUSL="target/x86_64-unknown-linux-musl/release/akurai-control"

  say "Build: static musl control-plane binary"
  rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
  cargo build --release --target x86_64-unknown-linux-musl -p akurai-control \
    || die "musl build failed"

  akurai-ec2 deploy-binary "$NAME" "$MUSL" "$PORT"
  akurai-ec2 nginx-proxy "$DOMAIN" "$PORT"
  say "TLS: requesting cert (skips gracefully if DNS hasn't propagated)"
  akurai-ec2 tls "$DOMAIN" || say "  TLS deferred — run 'akurai-ec2 tls $DOMAIN' once DNS resolves"
  say "Published → https://$DOMAIN"
}

# ── Changelog cut ───────────────────────────────────────────────────────────
# Stamp the "## [Unreleased]" section into a dated version section, leaving a
# fresh empty Unreleased on top.
cut_changelog() {
  local file="$1" verhead="$2"
  if [ ! -f "$file" ]; then say "  (no $file — skipping)"; return 0; fi
  awk -v vh="$verhead" '
    $0 == "## [Unreleased]" { print "## [Unreleased]"; print ""; print vh; next }
    { print }
  ' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
}

# ── `ec2` mode: publish only, no version change ─────────────────────────────
if [ "${1:-}" = "ec2" ]; then
  ec2_publish
  exit 0
fi

BUMP="${1:-patch}"
case "$BUMP" in patch|minor|major) ;; *) echo "usage: $0 [patch|minor|major|ec2]" >&2; exit 2 ;; esac

# ── 1. Quality gate ────────────────────────────────────────────────────────
say "Gate: rustfmt"
cargo fmt --all -- --check || die "formatting failed (run: cargo fmt --all)"

say "Gate: clippy (-D warnings)"
cargo clippy --all-targets -- -D warnings || die "clippy failed"

say "Gate: tests"
cargo test --workspace || die "tests failed"

# ── 2. Version bump (lockstep) ─────────────────────────────────────────────
CUR="$(tr -d '[:space:]' < VERSION)"
IFS='.' read -r MA MI PA <<< "$CUR"
case "$BUMP" in
  major) MA=$((MA+1)); MI=0; PA=0 ;;
  minor) MI=$((MI+1)); PA=0 ;;
  patch) PA=$((PA+1)) ;;
esac
NEW="$MA.$MI.$PA"
say "Version: $CUR → $NEW ($BUMP)"
printf '%s\n' "$NEW" > VERSION
# workspace.package.version is the single source crates inherit via version.workspace = true
sed -i -E "s/^version = \"$CUR\"/version = \"$NEW\"/" Cargo.toml

# ── 3. CHANGELOG ───────────────────────────────────────────────────────────
DATE="$(date +%Y-%m-%d)"
say "CHANGELOG: cutting [$NEW]"
cut_changelog "CHANGELOG.md" "## [$NEW] - $DATE"

# ── 4. Commit, tag, push ───────────────────────────────────────────────────
say "Git: commit + tag v$NEW"
git add -A
git commit -q -m "release: v$NEW"
git tag -a "v$NEW" -m "v$NEW"

if ! git remote get-url origin >/dev/null 2>&1; then
  if gh repo view "$REPO" >/dev/null 2>&1; then
    git remote add origin "https://github.com/$REPO.git"
  else
    say "Creating GitHub repo $REPO (private)"
    gh repo create "$REPO" --private --source=. --remote=origin
  fi
fi

say "Git: push"
git push -u origin HEAD
git push origin "v$NEW"

# ── 5. Publish live control plane ──────────────────────────────────────────
say "Publish: control plane"
ec2_publish

say "Released v$NEW ✓"
