#!/usr/bin/env bash
# Sync checkout to /homelab/civictech-crypto-engine without rsync.
# Preserves server-only paths: .env, data/, config/
set -euo pipefail

SRC="${1:-.}"
DEST="/homelab/civictech-crypto-engine"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

cd "$SRC"
tar cf - \
  --exclude='.git' \
  --exclude='.env' \
  --exclude='./data' \
  --exclude='./config' \
  . | tar xf - -C "$STAGE"

find "$DEST" -mindepth 1 -maxdepth 1 \
  ! -name '.env' ! -name 'data' ! -name 'config' \
  -exec rm -rf {} +

cp -a "$STAGE"/. "$DEST"/
