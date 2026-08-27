#!/bin/sh
# =============================================================================
# Инсталлер Splitbox для чистого VPS (Ubuntu/Debian).
#   curl -fsSL https://…/install.sh | sh
# =============================================================================
# Что делает: ставит docker (если нет), кладёт файлы в /opt/splitbox,
# генерирует .env с одноразовым токеном настройки, запускает стек и
# печатает ссылку на мастер. Идемпотентен: повторный запуск обновляет стек,
# не трогая настройки.
set -eu

REPO_URL="${SPLITBOX_REPO:-https://github.com/CHANGEME/splitbox}"
DIR=/opt/splitbox

say() { printf '\033[1;36m[splitbox]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[splitbox]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "запустите от root: curl … | sudo sh"

# --- docker ------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
    say "ставлю docker…"
    curl -fsSL https://get.docker.com | sh
fi
docker compose version >/dev/null 2>&1 || die "нужен docker compose v2"

# --- файлы -------------------------------------------------------------------
if [ -d "$DIR/.git" ]; then
    say "обновляю $DIR…"
    git -C "$DIR" pull -q
else
    say "клонирую в $DIR…"
    command -v git >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq git; }
    git clone -q "$REPO_URL" "$DIR"
fi
cd "$DIR/product" 2>/dev/null || cd "$DIR"

# --- .env --------------------------------------------------------------------
if [ ! -f .env ]; then
    TOKEN=$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    {
        echo "MODE=vps"
        echo "WG_PORT=51820"
        echo "WEB_PORT=8443"
        echo "SETUP_TOKEN=$TOKEN"
    } > .env
    chmod 600 .env
else
    TOKEN=$(sed -n 's/^SETUP_TOKEN=//p' .env)
fi

# --- порт 53 (только режим шлюза) --------------------------------------------
# systemd-resolved держит stub-listener на 127.0.0.53:53 и в host-network
# отбирает порт у AdGuard («address already in use» — поймано на учениях).
# В режиме vps порт 53 наружу не публикуется и конфликта нет.
MODE_NOW=$(sed -n 's/^MODE=//p' .env)
if [ "$MODE_NOW" = "lan-gateway" ] && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    if ! [ -f /etc/systemd/resolved.conf.d/splitbox.conf ]; then
        say "освобождаю порт 53 от systemd-resolved…"
        mkdir -p /etc/systemd/resolved.conf.d
        printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/splitbox.conf
        systemctl restart systemd-resolved
    fi
fi

# --- запуск ------------------------------------------------------------------
say "собираю и запускаю стек (первый раз — несколько минут)…"
if [ "$MODE_NOW" = "lan-gateway" ]; then
    docker compose -f compose.yaml -f compose.lan.yaml up -d --build
else
    docker compose up -d --build
fi

IP=$(curl -fsS -4 --max-time 10 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
WEB_PORT=$(sed -n 's/^WEB_PORT=//p' .env)

say ""
say "Готово. Откройте мастер настройки:"
say ""
say "    http://$IP:${WEB_PORT:-8443}/setup?token=$TOKEN"
say ""
say "Не забудьте открыть порты: ${WEB_PORT:-8443}/tcp (вебка, на время"
say "настройки) и 51820/udp (WireGuard, навсегда). После настройки"
say "вебка доступна и через WireGuard: http://10.99.0.1:${WEB_PORT:-8443}"
