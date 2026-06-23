#!/usr/bin/env bash
# Install a GitHub Actions self-hosted runner for wesley-ka/civictech-crypto-engine.
#
# Usage:
#   RUNNER_TOKEN='<registration-token>' bash scripts/install-github-runner.sh
#
# Get the token from GitHub → repo → Settings → Actions → Runners → New self-hosted runner.
set -euo pipefail

REPO="wesley-ka/civictech-crypto-engine"
RUNNER_DIR="${RUNNER_DIR:-/home/cursor-user/actions-runner}"
RUNNER_NAME="${RUNNER_NAME:-homeserver}"
RUNNER_LABELS="${RUNNER_LABELS:-self-hosted,linux,homeserver}"
RUNNER_VERSION="${RUNNER_VERSION:-2.323.0}"

if [[ -z "${RUNNER_TOKEN:-}" ]]; then
  echo "Set RUNNER_TOKEN from GitHub → Settings → Actions → Runners → New self-hosted runner" >&2
  exit 1
fi

mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

if [[ ! -f ./config.sh ]]; then
  echo "== Downloading actions-runner v${RUNNER_VERSION} =="
  curl -fsSL -o actions-runner.tar.gz \
    "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
  tar xzf actions-runner.tar.gz
  rm -f actions-runner.tar.gz
fi

if [[ ! -f ./.runner ]]; then
  echo "== Configuring runner =="
  ./config.sh \
    --url "https://github.com/${REPO}" \
    --token "$RUNNER_TOKEN" \
    --name "$RUNNER_NAME" \
    --labels "$RUNNER_LABELS" \
    --unattended \
    --replace
fi

echo "== Installing systemd user service =="
./svc.sh install
sudo loginctl enable-linger cursor-user

env XDG_RUNTIME_DIR="/run/user/1002" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1002/bus" \
  systemctl --user enable --now "actions.runner.${REPO//\//-}.${RUNNER_NAME}.service"

env XDG_RUNTIME_DIR="/run/user/1002" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1002/bus" \
  systemctl --user status "actions.runner.${REPO//\//-}.${RUNNER_NAME}.service" --no-pager

echo "Runner installed. Verify in GitHub → ${REPO} → Settings → Actions → Runners."
