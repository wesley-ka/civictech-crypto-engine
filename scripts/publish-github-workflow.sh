#!/usr/bin/env bash
# Upload deploy-homelab.yml to GitHub (requires PAT with workflow scope).
#
# Usage:
#   GITHUB_PAT_WORKFLOW='<pat-with-workflow-scope>' bash scripts/publish-github-workflow.sh
set -euo pipefail

REPO="wesley-ka/civictech-crypto-engine"
WORKFLOW_FILE="/homelab/civictech-crypto-engine/.github/workflows/deploy-homelab.yml"
TOKEN="${GITHUB_PAT_WORKFLOW:-${GITHUB_PAT:-}}"

if [[ -z "$TOKEN" ]]; then
  echo "Set GITHUB_PAT_WORKFLOW (or GITHUB_PAT) with workflow scope." >&2
  exit 1
fi

SHA=""
EXISTING=$(curl -sS \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer ${TOKEN}" \
  "https://api.github.com/repos/${REPO}/contents/.github/workflows/deploy-homelab.yml" || true)
SHA=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('sha',''))" <<<"$EXISTING" 2>/dev/null || true)

PAYLOAD=$(python3 -c "
import json, base64, pathlib, sys
content = pathlib.Path('${WORKFLOW_FILE}').read_bytes()
body = {
    'message': 'Add homelab auto-deploy workflow',
    'content': base64.b64encode(content).decode(),
}
sha = '${SHA}'
if sha:
    body['sha'] = sha
print(json.dumps(body))
")

RESP=$(curl -sS -X PUT \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer ${TOKEN}" \
  "https://api.github.com/repos/${REPO}/contents/.github/workflows/deploy-homelab.yml" \
  -d "$PAYLOAD")

python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('content',{}).get('path') or d.get('message','unknown'))" <<<"$RESP"
