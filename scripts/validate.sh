#!/usr/bin/env bash
# scripts/validate.sh — Post-deploy validation for AkurAI-VPN (control)
set -euo pipefail

DOMAIN="vpn.olibuijr.com"
PORT=8104
RED='\033[0;31m'; GRN='\033[0;32m'; NC='\033[0m'
pass=0; fail=0
pass_() { printf "  ${GRN}PASS${NC} %s\n" "$*"; ((pass++)); }
fail_() { printf "  ${RED}FAIL${NC} %s\n" "$*"; ((fail++)); }

echo "=== Post-deploy validation: AkurAI-VPN-control ==="

# 1. Systemd
systemctl is-active --quiet akurai-vpn-control.service 2>/dev/null && pass_ "systemd active" || fail_ "systemd not active"

# 2. Loopback
if curl -fsS --max-time 5 "http://127.0.0.1:${PORT}/" > /dev/null 2>&1; then
  pass_ "loopback serves"
else
  fail_ "loopback unreachable"
fi

# 3. Public HTTPS
if curl -fsS --max-time 10 "https://${DOMAIN}/" > /dev/null 2>&1; then
  pass_ "public HTTPS serves"
else
  fail_ "public HTTPS unreachable"
fi

# 4. VPN site also up (sister app on port 8097)
if systemctl is-active --quiet akurai-vpn-site.service 2>/dev/null; then
  pass_ "vpn-site systemd active"
else
  fail_ "vpn-site systemd not active"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GRN}Pass: $pass${NC}  ${RED}Fail: $fail${NC}"
[ "$fail" -eq 0 ] || exit 1
