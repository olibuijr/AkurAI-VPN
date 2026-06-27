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
command -v akurai-ec2 >/dev/null || { echo "✗ akurai-ec2 not on PATH — install the AkurAI ops CLI" >&2; exit 1; }
exec akurai-ec2 release "$@"
