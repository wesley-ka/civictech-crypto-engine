#!/usr/bin/env bash
# Publish deploy-homelab.yml to GitHub via git push.
#
# Requires a PAT that can push workflow files:
#   Classic PAT: repo + workflow scopes
#   Fine-grained PAT: Contents Read/Write + Actions Read/Write on this repo
#
# Usage:
#   bash scripts/publish-github-workflow.sh          # publish
#   bash scripts/publish-github-workflow.sh --check  # diagnose token only
set -euo pipefail

REPO="wesley-ka/civictech-crypto-engine"
BRANCH="${BRANCH:-main}"
WORKFLOW_FILE="/homelab/civictech-crypto-engine/.github/workflows/deploy-homelab.yml"
CHECK_ONLY=false

if [[ "${1:-}" == "--check" ]]; then
  CHECK_ONLY=true
fi

load_token() {
  TOKEN="${GITHUB_PAT_WORKFLOW:-${GITHUB_PAT:-}}"
  if [[ -z "$TOKEN" && -f /home/claw/openclaw-stack/.env ]]; then
    # shellcheck disable=SC1091
    source /home/claw/openclaw-stack/.env
    TOKEN="${GITHUB_PAT_WORKFLOW:-${GITHUB_PAT:-}}"
  fi
  if [[ -z "$TOKEN" ]]; then
    echo "Set GITHUB_PAT_WORKFLOW in /home/claw/openclaw-stack/.env" >&2
    exit 1
  fi
}

check_token() {
  local token="$1"
  local which="${2:-TOKEN}"

  echo "== Checking ${which} (length ${#token}, prefix ${token:0:4}…) =="

  local user_msg
  user_msg=$(curl -sS -H "Authorization: Bearer ${token}" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/user" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('login', d.get('message','?')))")
  echo "  user: ${user_msg}"

  local perms
  perms=$(curl -sS -H "Authorization: Bearer ${token}" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${REPO}" | python3 -c "
import json,sys
d=json.load(sys.stdin)
p=d.get('permissions') or {}
print('push=%s admin=%s' % (p.get('push'), p.get('admin')))
if d.get('message'): print('  repo error:', d['message'])
")

  echo "  repo: ${perms}"

  local tmp
  tmp=$(mktemp -d)
  if git clone --depth 1 -q "https://x-access-token:${token}@github.com/${REPO}.git" "$tmp" 2>/dev/null; then
    echo "  clone: OK"
    rm -rf "$tmp/.git"
    mkdir -p "$tmp/.github/workflows"
    cp "$WORKFLOW_FILE" "$tmp/.github/workflows/deploy-homelab.yml"
    git -C "$tmp" init -q
    git -C "$tmp" add .github/workflows/deploy-homelab.yml
    git -C "$tmp" -c user.email="cursor@local" -c user.name="cursor" \
      commit -q -m "test workflow push permissions"
    local push_out
    push_out=$(git -C "$tmp" push "https://x-access-token:${token}@github.com/${REPO}.git" "HEAD:${BRANCH}" 2>&1) || true
    if echo "$push_out" | grep -q "workflow scope"; then
      echo "  workflow push: FAIL — classic PAT missing workflow scope"
    elif echo "$push_out" | grep -qi "denied\|403\|Resource not accessible"; then
      echo "  workflow push: FAIL — token cannot write (fine-grained needs Contents + Actions Read/Write)"
    elif echo "$push_out" | grep -qE "main -> main|new branch"; then
      echo "  workflow push: OK"
    else
      echo "  workflow push: $(echo "$push_out" | tail -1)"
    fi
  else
    echo "  clone: FAIL — token cannot read repo"
  fi
  rm -rf "$tmp"
}

load_token
check_token "$TOKEN" "GITHUB_PAT_WORKFLOW"

if $CHECK_ONLY; then
  echo
  echo "If workflow push failed, create a new fine-grained PAT:"
  echo "  GitHub → Settings → Developer settings → Fine-grained tokens → Generate"
  echo "  Repository: civictech-crypto-engine only"
  echo "  Permissions: Contents Read/Write, Actions Read/Write, Metadata Read"
  echo "Or classic PAT with repo + workflow scopes."
  exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

git clone --depth 1 -b "$BRANCH" "https://x-access-token:${TOKEN}@github.com/${REPO}.git" "$TMP"
mkdir -p "$TMP/.github/workflows"
cp "$WORKFLOW_FILE" "$TMP/.github/workflows/deploy-homelab.yml"

cd "$TMP"
if git diff --quiet -- .github/workflows/deploy-homelab.yml 2>/dev/null && \
   git ls-files --error-unmatch .github/workflows/deploy-homelab.yml &>/dev/null; then
  echo "Workflow already up to date on ${BRANCH}"
  exit 0
fi

git add .github/workflows/deploy-homelab.yml
git -c user.email="cursor@local" -c user.name="cursor" \
  commit -m "Add homelab auto-deploy workflow"
git push origin "$BRANCH"

echo "Published .github/workflows/deploy-homelab.yml to ${REPO}@${BRANCH}"
