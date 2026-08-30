#!/bin/sh
# =============================================================================
# Splitbox — установка одной командой
#
#   curl -fsSL https://raw.githubusercontent.com/ensign-posture71/splitbox/main/install.sh | sudo sh
#
# Режим домашнего шлюза (коробка обслуживает всю локальную сеть):
#   curl -fsSL … | sudo sh -s -- --lan
# =============================================================================
# Что делает:
#   1. ставит docker, если его нет;
#   2. кладёт исходники в /opt/splitbox (скачивает архивом — git не нужен);
#   3. создаёт .env с одноразовым токеном мастера настройки;
#   4. в режиме шлюза освобождает порт 53 от systemd-resolved;
#   5. собирает и запускает стек, печатает ссылку на мастер.
#
# Идемпотентен: повторный запуск обновляет код и пересобирает стек,
# не трогая .env и настройки коробки (они живут в docker-томах).
set -eu

REPO="${SPLITBOX_REPO:-ensign-posture71/splitbox}"
BRANCH="${SPLITBOX_BRANCH:-main}"
DIR=/opt/splitbox
MODE_ARG=""

for arg in "$@"; do
    case "$arg" in
        --lan|--lan-gateway) MODE_ARG=lan-gateway ;;
        --vps)               MODE_ARG=vps ;;
        *) echo "неизвестный аргумент: $arg" >&2; exit 1 ;;
    esac
done

say() { printf '\033[1;36m[splitbox]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[splitbox]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "нужны права root: … | sudo sh"

# Запущен ли скрипт из распакованных исходников (а не через curl | sh).
# Проверяем именно файл $0: при пайпе $0 = «sh», такого файла рядом нет.
SRC=""
if [ -f "$0" ]; then
    _d=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    [ -f "$_d/compose.yaml" ] && SRC="$_d"
fi

# --- docker ------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
    say "ставлю docker…"
    curl -fsSL https://get.docker.com | sh
fi
docker compose version >/dev/null 2>&1 || die "нужен docker compose v2 (обновите docker)"

# --- исходники ---------------------------------------------------------------
if [ -n "$SRC" ]; then
    if [ "$SRC" != "$DIR" ]; then
        say "разворачиваю локальные исходники в $DIR…"
        mkdir -p "$DIR"
        (cd "$SRC" && tar cf - --exclude=.env --exclude=state .) | (cd "$DIR" && tar xf -)
    fi
else
    # Архивом, а не git clone: на чистой машине git может отсутствовать,
    # а curl уже есть — им же скачан этот скрипт.
    say "скачиваю splitbox ($REPO@$BRANCH)…"
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    curl -fsSL "https://codeload.github.com/$REPO/tar.gz/refs/heads/$BRANCH" \
        | tar xzf - -C "$TMP" || die "не удалось скачать исходники"
    UNPACKED=$(find "$TMP" -maxdepth 1 -mindepth 1 -type d | head -1)
    [ -f "$UNPACKED/compose.yaml" ] || die "архив без compose.yaml — репозиторий изменился?"
    mkdir -p "$DIR"
    (cd "$UNPACKED" && tar cf - --exclude=.env --exclude=state .) | (cd "$DIR" && tar xf -)
fi
cd "$DIR"

# --- .env --------------------------------------------------------------------
if [ ! -f .env ]; then
    TOKEN=$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    {
        echo "MODE=${MODE_ARG:-vps}"
        echo "WG_PORT=51820"
        echo "WEB_PORT=8443"
        echo "SETUP_TOKEN=$TOKEN"
    } > .env
    chmod 600 .env
else
    TOKEN=$(sed -n 's/^SETUP_TOKEN=//p' .env)
    # Повторный запуск с флагом меняет режим существующей установки.
    if [ -n "$MODE_ARG" ]; then
        sed -i.bak "s/^MODE=.*/MODE=$MODE_ARG/" .env && rm -f .env.bak
    fi
fi
MODE_NOW=$(sed -n 's/^MODE=//p' .env)
WEB_PORT=$(sed -n 's/^WEB_PORT=//p' .env)

# --- порт 53 (только режим шлюза) --------------------------------------------
# systemd-resolved держит stub-listener на 127.0.0.53:53 и в host-network
# отбирает порт у AdGuard («address already in use»). В режиме vps порт 53
# наружу не публикуется, конфликта нет.
if [ "$MODE_NOW" = "lan-gateway" ] && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    if [ ! -f /etc/systemd/resolved.conf.d/splitbox.conf ]; then
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

IP=$(curl -fsS -4 --max-time 10 https://ifconfig.me 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')

say ""
say "Готово. Откройте мастер настройки:"
say ""
say "    http://${IP:-АДРЕС-СЕРВЕРА}:${WEB_PORT:-8443}/setup?token=$TOKEN"
say ""
if [ "$MODE_NOW" = "lan-gateway" ]; then
    say "Режим: домашний шлюз. После настройки укажите в роутере адрес этой"
    say "машины как шлюз и DNS для локальной сети."
else
    say "Режим: VPS. Откройте порты ${WEB_PORT:-8443}/tcp (вебка, на время"
    say "настройки) и 51820/udp (WireGuard, навсегда). После настройки вебка"
    say "доступна и через WireGuard: http://10.99.0.1:${WEB_PORT:-8443}"
fi
