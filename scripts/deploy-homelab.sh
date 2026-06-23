#!/usr/bin/env bash
# Build, sync Quadlet units, and restart civictech-crypto-engine on homeserver.
# Used by GitHub Actions (self-hosted runner) and manual deploys.
set -euo pipefail

APP_DIR="${APP_DIR:-/homelab/civictech-crypto-engine}"
IMAGE="localhost/civictech-crypto-engine:latest"
UNIT_DST_DIR="/etc/containers/systemd/users/1002"
CURSOR_UID="${CURSOR_UID:-1002}"
SERVICE="civictech-crypto-engine.service"
HEALTH_URL="http://127.0.0.1:8085/api/v1/health"
HEALTH_RETRIES=12
HEALTH_INTERVAL=5

cursor_systemctl() {
  env XDG_RUNTIME_DIR="/run/user/${CURSOR_UID}" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${CURSOR_UID}/bus" \
    systemctl --user "$@"
}

log_fail() {
  echo "Deploy failed — last 50 journal lines:" >&2
  cursor_systemctl status "$SERVICE" --no-pager >&2 || true
  cursor_systemctl journalctl -u "$SERVICE" -n 50 --no-pager >&2 || true
}

trap 'log_fail' ERR

echo "== Building image =="
/usr/bin/podman build -t "$IMAGE" "$APP_DIR"

echo "== Syncing Quadlet units =="
/usr/bin/podman rm -f civictech-crypto-engine 2>/dev/null || true
sudo cp "$APP_DIR/containers/civictech-crypto-engine-data.volume" "$UNIT_DST_DIR/"
sudo cp "$APP_DIR/containers/civictech-crypto-engine.container" "$UNIT_DST_DIR/"
sudo systemctl daemon-reload
cursor_systemctl daemon-reload

echo "== Restarting service =="
if cursor_systemctl is-enabled "$SERVICE" &>/dev/null; then
  cursor_systemctl restart "$SERVICE"
else
  bash "$APP_DIR/scripts/install-quadlet.sh"
fi

echo "== Waiting for health =="
for i in $(seq 1 "$HEALTH_RETRIES"); do
  if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
    curl -sf "$HEALTH_URL" | python3 -m json.tool
    echo "Deploy OK"
    exit 0
  fi
  echo "  attempt $i/$HEALTH_RETRIES — not ready yet"
  sleep "$HEALTH_INTERVAL"
done

echo "Health check failed after $((HEALTH_RETRIES * HEALTH_INTERVAL))s" >&2
log_fail
exit 1
