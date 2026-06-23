#!/usr/bin/env bash
# Create or update NPM proxy host for api.awka.dev.
#
# NPM runs in the root Podman namespace on npm-net. Rootless apps publish ports
# on the host; reach them from NPM via the bridge gateway (10.89.0.1), NOT
# host.containers.internal (that only works in some rootless setups).
#
# Usage:
#   NPM_IDENTITY='you@example.com' NPM_SECRET='your-password' \
#     bash /homelab/civictech-crypto-engine/scripts/configure-npm-proxy.sh
set -euo pipefail

NPM_URL="${NPM_URL:-http://127.0.0.1:81}"
DOMAIN="${DOMAIN:-api.awka.dev}"
FORWARD_HOST="${FORWARD_HOST:-10.89.0.1}"
FORWARD_PORT="${FORWARD_PORT:-8085}"

if [[ -z "${NPM_IDENTITY:-}" || -z "${NPM_SECRET:-}" ]]; then
  echo "Set NPM_IDENTITY and NPM_SECRET (NPM admin email and password)." >&2
  exit 1
fi

TOKEN=$(curl -sf -X POST "$NPM_URL/api/tokens" \
  -H 'Content-Type: application/json' \
  -d "{\"identity\":\"$NPM_IDENTITY\",\"secret\":\"$NPM_SECRET\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

AUTH=(-H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json')

EXISTING_ID=$(curl -sf "$NPM_URL/api/nginx/proxy-hosts" "${AUTH[@]}" \
  | python3 -c "
import sys, json
hosts = json.load(sys.stdin)
for h in hosts:
    if '$DOMAIN' in h.get('domain_names', []):
        print(h['id'])
        break
")

PAYLOAD=$(python3 -c "
import json
print(json.dumps({
    'domain_names': ['$DOMAIN'],
    'forward_scheme': 'http',
    'forward_host': '$FORWARD_HOST',
    'forward_port': $FORWARD_PORT,
    'access_list_id': 0,
    'certificate_id': 0,
    'ssl_forced': False,
    'caching_enabled': False,
    'block_exploits': True,
    'allow_websocket_upgrade': False,
    'http2_support': False,
    'hsts_enabled': False,
    'meta': {'letsencrypt_agree': False, 'dns_challenge': False},
}))
")

if [[ -n "$EXISTING_ID" ]]; then
  echo "Updating existing proxy host id=$EXISTING_ID ..."
  curl -sf -X PUT "$NPM_URL/api/nginx/proxy-hosts/$EXISTING_ID" "${AUTH[@]}" -d "$PAYLOAD" | python3 -m json.tool
else
  echo "Creating proxy host ..."
  curl -sf -X POST "$NPM_URL/api/nginx/proxy-hosts" "${AUTH[@]}" -d "$PAYLOAD" | python3 -m json.tool
fi

echo "NPM proxy host $DOMAIN -> $FORWARD_HOST:$FORWARD_PORT"
sleep 2
curl -sf -H "Host: $DOMAIN" "http://127.0.0.1:80/api/v1/health" | python3 -m json.tool
