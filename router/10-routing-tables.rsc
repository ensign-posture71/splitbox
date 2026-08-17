# =============================================================================
# 10 — Таблицы маршрутизации (шаг 1.1)
# =============================================================================
# Идемпотентно: повторный запуск не создаёт дублей.
#
# table_vps  — «за рубеж», next-hop = sing-box VM (192.168.88.6)
# table_work — «работа»,   next-hop = wg-work (ещё не существует, D5)
# main       — всё остальное (direct через WAN), не трогаем
# =============================================================================

/routing table
:if ([:len [find where name="table_vps"]] = 0) do={
  add name=table_vps fib comment="policy: abroad -> sing-box VM"
}
:if ([:len [find where name="table_work"]] = 0) do={
  add name=table_work fib comment="policy: work -> wg-work"
}

# -----------------------------------------------------------------------------
# Маршруты в table_vps
# -----------------------------------------------------------------------------
# ФАЗА 1 (сейчас, VM ещё нет): abroad-трафик уходит тем же путём, что и direct.
#   Смысл: классификатор можно проверить по счётчикам mangle, НЕ разрывая связь.
#   Без активного маршрута в таблице помеченные пакеты просто дропались бы.
#
# ФАЗА 2 (после шага 3.1): раскомментировать маршрут на VM (distance=1),
#   маршрут ниже останется как fail-open (distance=10) — падение VM вернёт
#   abroad в direct, а не убьёт его. Это и есть D1.
#
# ВНИМАНИЕ: шлюз WAN получен по DHCP (91.200.224.129, O8). Если провайдер его
#   сменит — маршрут протухнет. На шаге 4 заменить на скрипт синхронизации
#   из main-таблицы либо на netwatch-управление классификатором.
# -----------------------------------------------------------------------------

/ip route
:if ([:len [find where routing-table="table_vps" && comment~"fail-open"]] = 0) do={
  add dst-address=0.0.0.0/0 gateway=91.200.224.129 routing-table=table_vps \
      distance=10 comment="table_vps fail-open: abroad -> WAN direct"
}

# ФАЗА 2 — включить после того, как VM поднимется и начнёт отвечать на ping:
# /ip route add dst-address=0.0.0.0/0 gateway=192.168.88.6 routing-table=table_vps \
#     distance=1 check-gateway=ping comment="table_vps primary: abroad -> sing-box VM"

# table_work маршрутов пока не получает — wg-work не существует (D5).
# После получения конфига от работы:
# /ip route add dst-address=0.0.0.0/0 gateway=wg-work routing-table=table_work distance=1
