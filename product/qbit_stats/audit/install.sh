#!/bin/sh
set -eu
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -d -m 0755 /opt/qbittorrent-audit /opt/qbittorrent-audit/logs /opt/qbittorrent-audit/data /opt/qbittorrent-audit/config
if [ "$base" != "/opt/qbittorrent-audit" ]; then
  install -m 0644 "$base/Caddyfile" /opt/qbittorrent-audit/Caddyfile
  install -m 0644 "$base/compose.yaml" /opt/qbittorrent-audit/compose.yaml
fi
cd /opt/qbittorrent-audit
docker compose -f compose.yaml up -d
