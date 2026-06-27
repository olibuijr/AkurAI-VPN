#!/usr/bin/env bash
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
