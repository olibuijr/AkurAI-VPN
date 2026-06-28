#!/usr/bin/env bash
# scripts/validate.sh — Post-deploy validation for AkurAI-VPN control plane
# Canonical pattern from AkurAI-Framework/scripts/validate.sh with OIDC auth
set -euo pipefail

: "${DOMAIN:=vpn.olibuijr.com}"
: "${PORT:=8104}"
: "${APP_NAME:=akurai-vpn-control}"
: "${SSH_HOST:=akurai-mail}"
RED='\033[0;31m'; GRN='\033[0;32m'; NC='\033[0m'
pass=0; fail=0
pass_() { printf "  ${GRN}PASS${NC} %s\n" "$*"; pass=$((pass + 1)); }
fail_() { printf "  ${RED}FAIL${NC} %s\n" "$*"; fail=$((fail + 1)); }

remote() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "${APP_NAME}.service" 2>/dev/null; then
    "$@"
  else
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$SSH_HOST" "$@"
  fi
}

echo "=== Post-deploy validation: ${APP_NAME} ==="

# 1. Systemd (both control plane + sister site)
remote systemctl is-active --quiet "${APP_NAME}.service" 2>/dev/null && pass_ "systemd active" || fail_ "${APP_NAME} not active"
remote systemctl is-active --quiet akurai-vpn-site.service 2>/dev/null && pass_ "vpn-site systemd active" || fail_ "vpn-site not active"

# 2. Loopback + public health (uses /health not /api/health)
remote curl -fsS --max-time 5 "http://127.0.0.1:${PORT}/api/health" > /dev/null 2>&1 && pass_ "loopback health" || fail_ "loopback unreachable"
curl -fsS --max-time 10 "https://${DOMAIN}/api/health" > /dev/null 2>&1 && pass_ "public health" || fail_ "public unreachable"

# 3. Status JSON schema
STATUS=$(curl -fsS --max-time 5 "https://${DOMAIN}/api/health" 2>/dev/null || echo '{}')
echo "$STATUS" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for k in ['status','app','version']:
    assert k in d, f'missing key: {k}'
" 2>/dev/null && pass_ "status JSON schema valid" || fail_ "status JSON schema invalid"

# 4. OIDC login — 302 redirect to IDP authorize
LOGIN_REDIR=$(curl -sS -o /dev/null -w '%{http_code}:%{redirect_url}' --max-time 5 "https://${DOMAIN}/login" 2>/dev/null || echo "000:")
LOGIN_STATUS="${LOGIN_REDIR%%:*}"
LOGIN_URL="${LOGIN_REDIR#*:}"
if [ "$LOGIN_STATUS" = "302" ] && echo "$LOGIN_URL" | grep -q 'auth.olibuijr.com/authorize'; then
  pass_ "OIDC /login → 302 to IDP authorize"
else
  fail_ "OIDC /login → ${LOGIN_STATUS} (expected 302 to IDP)"
fi

# 5. Authorize URL has required params
if echo "$LOGIN_URL" | grep -q 'client_id=' && echo "$LOGIN_URL" | grep -q 'redirect_uri=' && echo "$LOGIN_URL" | grep -q 'state='; then
  pass_ "authorize URL has client_id, redirect_uri, state"
else
  fail_ "authorize URL missing required params"
fi

# 6. Protected route redirects to login
DASH_CODE=$(curl -sS -o /dev/null -w '%{http_code}:%{redirect_url}' --max-time 5 "https://${DOMAIN}/dashboard" 2>/dev/null || echo "000:")
DASH_STATUS="${DASH_CODE%%:*}"
DASH_URL="${DASH_CODE#*:}"
[ "$DASH_STATUS" = "302" ] && echo "$DASH_URL" | grep -q '/login$' && pass_ "/dashboard → 302 to /login (no auth)" || fail_ "/dashboard → ${DASH_STATUS} (expected 302)"

# 7. Logout clears cookie
LOGOUT_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "https://${DOMAIN}/auth/logout" 2>/dev/null)
[ "${LOGOUT_CODE:-000}" = "302" ] && pass_ "/auth/logout → 302" || fail_ "/auth/logout → ${LOGOUT_CODE}"

# 8. Callback without code returns an intentional error page
CALLBACK_TMP=$(mktemp)
CALLBACK_CODE=$(curl -sS -o "$CALLBACK_TMP" -w '%{http_code}' --max-time 5 "https://${DOMAIN}/auth/callback" 2>/dev/null || echo "000")
if [ "$CALLBACK_CODE" = "500" ] && grep -qi 'error\|missing\|Invalid' "$CALLBACK_TMP"; then
  pass_ "/auth/callback (no code) shows error"
else
  fail_ "/auth/callback → ${CALLBACK_CODE} (expected 500 error page)"
fi
rm -f "$CALLBACK_TMP"

# 9. API endpoints require auth
ENDPOINTS_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "https://${DOMAIN}/api/endpoints" 2>/dev/null)
[ "${ENDPOINTS_CODE:-000}" = "302" ] && pass_ "/api/endpoints → 302 (no auth)" || fail_ "/api/endpoints → ${ENDPOINTS_CODE} (expected 302)"

echo "━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GRN}Pass: $pass${NC}  ${RED}Fail: $fail${NC}"
[ "$fail" -eq 0 ] || exit 1
