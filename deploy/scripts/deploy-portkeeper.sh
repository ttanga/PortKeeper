#!/usr/bin/env bash
set -euo pipefail

BINARY_SOURCE=/tmp/portkeeper-upload
BINARY_TARGET=/app/golang/PortKeeper/portkeeper
BINARY_NEW=/app/golang/PortKeeper/portkeeper.new
BINARY_BACKUP=/app/golang/PortKeeper/portkeeper.previous
SERVICE=portkeeper

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root." >&2
  exit 1
fi

if [[ ! -f "$BINARY_SOURCE" || -L "$BINARY_SOURCE" ]]; then
  echo "Expected regular upload file at $BINARY_SOURCE." >&2
  exit 1
fi

if [[ ! -s /app/golang/PortKeeper/config.yaml ]]; then
  echo "Missing runtime config: /app/golang/PortKeeper/config.yaml" >&2
  exit 1
fi

install -o root -g portkeeper -m 0750 "$BINARY_SOURCE" "$BINARY_NEW"
rm -f "$BINARY_SOURCE"

HAD_PREVIOUS=0
if [[ -f "$BINARY_TARGET" ]]; then
  cp -a "$BINARY_TARGET" "$BINARY_BACKUP"
  HAD_PREVIOUS=1
fi

mv -f "$BINARY_NEW" "$BINARY_TARGET"

if systemctl restart "$SERVICE" && systemctl is-active --quiet "$SERVICE"; then
  rm -f "$BINARY_BACKUP"
  echo "PortKeeper deployment successful."
  systemctl --no-pager --full status "$SERVICE"
  exit 0
fi

echo "New version failed to start; attempting rollback." >&2
if [[ $HAD_PREVIOUS -eq 1 ]]; then
  mv -f "$BINARY_BACKUP" "$BINARY_TARGET"
  systemctl restart "$SERVICE" || true
else
  rm -f "$BINARY_TARGET"
  systemctl stop "$SERVICE" || true
fi

journalctl -u "$SERVICE" -n 60 --no-pager >&2 || true
exit 1
