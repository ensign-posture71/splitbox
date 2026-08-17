#!/bin/bash
# =============================================================================
# Health-check туннеля — слой 2 отказоустойчивости
# =============================================================================
# Слой 1 (маршрутный) уже работает: у маршрута на 192.168.88.6 в table_vps
# стоит check-gateway=ping, под ним маршрут на WAN с distance=10. Умер
# контейнер — трафик сам уходит напрямую.
#
# Дыра, которую закрывает этот скрипт: контейнер жив и пингуется, а туннель
# сломан (упал sing-box, недоступен VPS, протух DDNS — O15). Роутер видит
# успешный ping, держит маршрут активным, и abroad-трафик уходит в никуда.
#
# Решение: контейнер сам проверяет туннель НАСТОЯЩИМ запросом наружу и,
# если тот сломан, перестаёт отвечать роутеру на ICMP. Дальше срабатывает
# слой 1. Роутеру не нужно уметь ничего нового — он просто перестаёт
# видеть шлюз.
#
# Почему не проверяем «работает ли процесс sing-box»: процесс может быть жив
# при мёртвом туннеле. Проверять надо результат, а не признак.
#
# Почему нужны два подряд провала: одиночный сбой (моргнул VPS, потерялся
# пакет) не должен дёргать маршрутизацию всего дома.
# =============================================================================

set -u

PROBE_URL="https://www.cloudflare.com/cdn-cgi/trace"
PROXY="socks5h://127.0.0.1:1080"
TIMEOUT=10
ROUTER="192.168.88.1"
STATE="/run/tunnel-health.fails"
FAILS_TO_BLOCK=2

NFT_TABLE="ip health"

log() { logger -t tunnel-health "$1"; echo "$1"; }

block_icmp() {
    # Роутер перестаёт видеть шлюз -> check-gateway гасит маршрут -> fail-open.
    nft list table $NFT_TABLE >/dev/null 2>&1 && return 0
    nft -f - <<EOF
table $NFT_TABLE {
    chain input {
        type filter hook input priority filter; policy accept;
        ip saddr $ROUTER icmp type echo-request drop
    }
}
EOF
    log "ТУННЕЛЬ СЛОМАН: ICMP от роутера заблокирован, маршрут уйдёт в fail-open"
}

unblock_icmp() {
    if nft list table $NFT_TABLE >/dev/null 2>&1; then
        nft delete table $NFT_TABLE
        log "туннель восстановлен: ICMP разблокирован, маршрут вернётся"
    fi
}

fails=0
[ -r "$STATE" ] && fails=$(cat "$STATE" 2>/dev/null || echo 0)

if curl -sS -4 --proxy "$PROXY" --max-time "$TIMEOUT" -o /dev/null "$PROBE_URL" 2>/dev/null; then
    echo 0 > "$STATE"
    unblock_icmp
    exit 0
fi

fails=$((fails + 1))
echo "$fails" > "$STATE"
log "проверка туннеля не прошла ($fails подряд)"

[ "$fails" -ge "$FAILS_TO_BLOCK" ] && block_icmp
exit 0
