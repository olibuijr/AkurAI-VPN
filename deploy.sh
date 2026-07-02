#!/usr/bin/env bash
# Deploy rules of conduct:
# - Read AGENTS.md and canonical Notes/docs before changing or deploying.
# - Never print, commit, or copy secrets; use passvault/env files only.
# - Preserve env files, service users, user data, and databases; snapshot state before risky swaps.
# - Verify ports, DNS, TLS, and systemd unit names before changing routes or services.
# - Use managed services only (systemd/pm2); no nohup, background shells, or ad hoc daemons.
# - Run gates and health checks; if deploy fails, stop and roll back rather than improvising.
# - Keep deploy behavior unchanged unless the task explicitly asks for deploy logic changes.
# deploy.sh — thin shim. The release logic now lives ONCE in `akurai-ec2 release`,
# driven by this repo's ./akurai-deploy.toml (no more per-project release bash).
#
#   ./deploy.sh [patch|minor|major]   full release: gate → bump → changelog →
#                                     tag → push → deploy (default: patch)
#   ./deploy.sh ec2|publish           ship the current binary, no version bump
#   ./deploy.sh <level> --dry-run     preview without writing/pushing/deploying
#
# Config: akurai-deploy.toml. Engine: `akurai-ec2 release` (see _AWSEC2 skill).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
AKURAI_EC2="${AKURAI_EC2:-$(command -v akurai-ec2 || true)}"
if [ -z "$AKURAI_EC2" ] && [ -x "../akurai-ec2/bin/akurai-ec2" ]; then
  AKURAI_EC2="../akurai-ec2/bin/akurai-ec2"
fi
[ -n "$AKURAI_EC2" ] || { echo "✗ akurai-ec2 not found — install the AkurAI ops CLI or set AKURAI_EC2" >&2; exit 1; }

dry_run=0
for arg in "$@"; do
  [ "$arg" = "--dry-run" ] && dry_run=1
done

"$AKURAI_EC2" release "$@"

if [ "$dry_run" = 1 ]; then
  exit 0
fi

TARGET="${AKURAI_VPN_TARGET:-x86_64-unknown-linux-musl}"
REMOTE_TMP="/tmp/akurai-vpn-sidecars-$$"

echo "▸ build sidecars: akurai-node + akurai-relay"
rustup target add "$TARGET" >/dev/null 2>&1 || true
cargo build --release --target "$TARGET" -p akurai-node -p akurai-relay

echo "▸ deploy sidecars to EC2"
"$AKURAI_EC2" ssh "mkdir -p '$REMOTE_TMP'"
"$AKURAI_EC2" ship "target/$TARGET/release/akurai-node" "$REMOTE_TMP/akurai-node"
"$AKURAI_EC2" ship "target/$TARGET/release/akurai-relay" "$REMOTE_TMP/akurai-relay"

"$AKURAI_EC2" ssh "set -euo pipefail
sudo install -m 0755 -o root -g root '$REMOTE_TMP/akurai-node' /usr/local/bin/akurai-node
sudo mkdir -p /opt/akurai-peer/bin /opt/akurai-peer/config /opt/akurai-vpn-relay/bin
sudo install -m 0755 -o root -g root '$REMOTE_TMP/akurai-node' /opt/akurai-peer/bin/akurai-node
sudo install -m 0755 -o ubuntu -g ubuntu '$REMOTE_TMP/akurai-relay' /opt/akurai-vpn-relay/bin/akurai-relay
sudo tee /opt/akurai-peer/config/network.conf >/dev/null <<'EOF'
overlay_ip=100.88.0.4
relay=127.0.0.1:51820
control=https://vpn.olibuijr.com
EOF
sudo systemctl restart akurai-vpn-relay.service
sudo systemctl restart akurai-node.service
sleep 2
systemctl is-active akurai-vpn-relay.service
systemctl is-active akurai-node.service
/opt/akurai-vpn-relay/bin/akurai-relay version
/usr/local/bin/akurai-node version
rm -rf '$REMOTE_TMP'"
