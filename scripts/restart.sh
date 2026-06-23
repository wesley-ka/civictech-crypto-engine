#!/usr/bin/env bash
# Run civictech-crypto-engine via Podman (use until systemd Quadlet is installed).
set -euo pipefail

APP_DIR="/homelab/civictech-crypto-engine"
IMAGE="localhost/civictech-crypto-engine:latest"
VOLUME="civictech-crypto-engine-data"

/usr/bin/podman volume exists "$VOLUME" 2>/dev/null || /usr/bin/podman volume create "$VOLUME"

/usr/bin/podman build -t "$IMAGE" "$APP_DIR"
/usr/bin/podman rm -f civictech-crypto-engine 2>/dev/null || true
/usr/bin/podman run -d \
  --name civictech-crypto-engine \
  --replace \
  --env-file "$APP_DIR/.env" \
  -e TZ=Europe/Amsterdam \
  -e PORT=8080 \
  -p 8085:8080 \
  -v civictech-crypto-engine-data:/app/local-storage:rw \
  "$IMAGE"

sleep 8
curl -sf "http://127.0.0.1:8085/api/v1/health" | python3 -m json.tool
