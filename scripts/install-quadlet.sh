#!/usr/bin/env bash
# Install civictech-crypto-engine as a cursor-user systemd Quadlet.
set -euo pipefail

UNIT_DST_DIR="/etc/containers/systemd/users/1002"
UNIT_SRC="/homelab/civictech-crypto-engine/containers/civictech-crypto-engine.container"
UNIT_DST="$UNIT_DST_DIR/civictech-crypto-engine.container"

# Stop ad-hoc container if present so the Quadlet service can bind port 8085.
/usr/bin/podman rm -f civictech-crypto-engine 2>/dev/null || true

sudo cp /homelab/civictech-crypto-engine/containers/civictech-crypto-engine-data.volume "$UNIT_DST_DIR/"
sudo cp "$UNIT_SRC" "$UNIT_DST"
sudo systemctl daemon-reload
sudo loginctl enable-linger cursor-user
sudo -u cursor-user env XDG_RUNTIME_DIR=/run/user/1002 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1002/bus \
  systemctl --user daemon-reload
sudo -u cursor-user env XDG_RUNTIME_DIR=/run/user/1002 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1002/bus \
  systemctl --user enable --now civictech-crypto-engine.service
sudo -u cursor-user env XDG_RUNTIME_DIR=/run/user/1002 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1002/bus \
  systemctl --user status civictech-crypto-engine.service --no-pager
