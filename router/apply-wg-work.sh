#!/usr/bin/env bash
# Применяет router/15-wg-work.rsc, подставив ключи и endpoint из
# secrets/staff_lyurov2.conf. Ключи в Git не попадают: подстановка — во
# временный файл, который удаляется после импорта.
set -euo pipefail
cd "$(dirname "$0")/.."

CONF=secrets/staff_lyurov2.conf
ROUTER=admin@192.168.88.1

priv=$(sed -n 's/^PrivateKey[[:space:]]*=[[:space:]]*//p' "$CONF")
pub=$(sed -n 's/^PublicKey[[:space:]]*=[[:space:]]*//p' "$CONF")
endpoint=$(sed -n 's/^Endpoint[[:space:]]*=[[:space:]]*//p' "$CONF")
host=${endpoint%:*}
port=${endpoint##*:}

[ -n "$priv" ] && [ -n "$pub" ] && [ -n "$host" ] && [ -n "$port" ] || {
  echo "не смог разобрать $CONF" >&2; exit 1; }

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
sed -e "s|@@WG_WORK_PRIVATE_KEY@@|$priv|" \
    -e "s|@@WG_WORK_PEER_PUBLIC_KEY@@|$pub|" \
    -e "s|@@WG_WORK_ENDPOINT_HOST@@|$host|" \
    -e "s|@@WG_WORK_ENDPOINT_PORT@@|$port|" \
    router/15-wg-work.rsc > "$tmp"

echo "== бэкап =="
ssh "$ROUTER" '/system backup save name=pre-wg-work'

echo "== заливка и импорт =="
scp -q "$tmp" "$ROUTER":15-wg-work.rsc
ssh "$ROUTER" '/import file-name=15-wg-work.rsc'
ssh "$ROUTER" '/file remove [find where name="15-wg-work.rsc"]'

echo "== состояние =="
ssh "$ROUTER" '/interface wireguard print; /interface wireguard peers print'
