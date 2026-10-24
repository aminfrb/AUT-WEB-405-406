#!/usr/bin/env bash
# Walks through the whole flow against a running proxy.
#
#   ./scripts/demo.sh                          # proxy on http://localhost
#   BASE_URL=http://localhost:8080 ./scripts/demo.sh
#
# Needs only bash and curl.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost}"
USERNAME="${DEMO_USER:-amin}"
PASSWORD="${DEMO_PASSWORD:-ie-http-1405}"

step() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
show() { curl -sS -w '\n-> HTTP %{http_code}\n' "$@"; }

step "1) Request without a token is rejected (expect 401 + WWW-Authenticate)"
show -i "$BASE_URL/get" | grep -Ei '^(HTTP|www-authenticate)|error|->'

step "2) Login with a wrong password (expect 401)"
show -X POST "$BASE_URL/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USERNAME\",\"password\":\"wrong\"}"

step "3) Login with the right password (expect 200 + access_token)"
LOGIN=$(curl -sS -X POST "$BASE_URL/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
echo "$LOGIN"
TOKEN=$(printf '%s' "$LOGIN" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$TOKEN" ] || { echo "login failed"; exit 1; }

step "4) Same request with the token (expect 200; httpbin sees X-Authenticated-User, not the token)"
show "$BASE_URL/headers" -H "Authorization: Bearer $TOKEN" -H "X-Authenticated-User: admin"

step "5) Other methods and paths work too (POST /anything)"
show -X POST "$BASE_URL/anything?from=demo" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"hello":"legacy"}' | grep -E '"(method|url|json|hello)"|->'

step "6) Forged token: payload changed to sub=admin, old signature kept (expect 401 invalid_token)"
b64url() { base64 | tr '+/' '-_' | tr -d '=\n'; }
HEADER=${TOKEN%%.*}
SIGNATURE=${TOKEN##*.}
FORGED_PAYLOAD=$(printf '{"sub":"admin","iss":"jwt-proxy","aud":"legacy-httpbin","exp":4102444800}' | b64url)
show "$BASE_URL/get" -H "Authorization: Bearer $HEADER.$FORGED_PAYLOAD.$SIGNATURE"

step "7) Status codes from the legacy service pass through unchanged (expect 418)"
show -o /dev/null "$BASE_URL/status/418" -H "Authorization: Bearer $TOKEN"
