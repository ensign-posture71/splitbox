# =============================================================================
# 31 — Миграция классификатора abroad на stateless-схему (починка O28)
# =============================================================================
# ПРОБЛЕМА (O30, подтверждена захватом пакетов и логом firewall):
# контейнер и клиенты в одной подсети, поэтому ответы контейнер отправляет
# клиенту напрямую по L2, минуя роутер. Роутер видит только половину
# соединения, его conntrack застревает в SYN_SENT, следующий пакет клиента
# получает connection-state=invalid, connection-mark теряется, и пакет
# уходит в main → WAN, где его дропает «drop invalid».
# Наблюдалось: 3077 invalid-дропов за окно одного запроса при базовом
# уровне 4 пакета за 10 секунд.
#
# РЕШЕНИЕ: перестать зависеть от conntrack там, где он принципиально
# не может работать.
#   1) метка маршрутизации ставится напрямую по dst-address-list,
#      без mark-connection — состояние соединения больше не нужно;
#   2) abroad-потоки исключаются из conntrack через raw notrack —
#      нечему становиться невалидным.
#
# ПОЧЕМУ ЭТО НЕ НАРУШАЕТ §4.1 АРХИТЕКТУРЫ:
# там связка mark-connection → mark-routing предписана с обоснованием
# «на роутере есть NAT, и routing-rules ломают симметрию соединений».
# К abroad-трафику это не относится: он уходит на контейнер в LAN,
# а не в WAN, masquerade его не касается, и NAT в этом пути отсутствует.
# Симметрия здесь уже нарушена физически (ответ идёт мимо роутера),
# и никакая работа с conntrack её не восстановит.
#
# ПРЕДОХРАНИТЕЛИ, которые остаются нетронутыми:
#   policy 00 — локальные назначения не маркируются;
#   policy 01 — трафик самого шлюза не маркируется.
# Оба идут раньше и работают без conntrack.
# =============================================================================

# --- 1. Исключить abroad-потоки из conntrack --------------------------------
# src-address=!192.168.88.6 обязателен: собственный трафик контейнера уходит
# в WAN через masquerade, а NAT без conntrack работать не может. Снять
# отслеживание с него означало бы оборвать сам туннель.
/ip firewall raw
:if ([:len [find where comment~"^policy raw"]] = 0) do={
  add chain=prerouting action=notrack dst-address-list=abroad \
      in-interface-list=LAN src-address=!192.168.88.6 \
      comment="policy raw: abroad вне conntrack (O30)"
}

# --- 2. Stateless-метка маршрутизации ---------------------------------------
/ip firewall mangle
:if ([:len [find where comment~"^policy 12"]] = 0) do={
  add chain=prerouting action=mark-routing new-routing-mark=table_vps \
      passthrough=no dst-address-list=abroad in-interface-list=LAN \
      place-before=[:pick [find where comment~"^policy 10"] 0] \
      comment="policy 12: abroad -> table_vps (stateless, O30)"
}

# --- 3. Выключить прежнюю пару, но не удалять -------------------------------
# Оставлены выключенными сознательно: если stateless-схема себя не оправдает,
# откат — это включить их и выключить policy 12, без восстановления из бэкапа.
:foreach r in=[/ip firewall mangle find where comment~"^policy 1[01]"] do={
  /ip firewall mangle set $r disabled=yes
}

# Проверка после применения:
#   /ip firewall raw print stats
#   /ip firewall mangle print stats where !dynamic
#   /ip firewall filter print stats chain=forward where connection-state=invalid
# Ожидается: счётчик policy 12 растёт, invalid-дропы вернулись к единицам.
