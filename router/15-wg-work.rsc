# =============================================================================
# 15 — Туннель «на работу» wg-work (закрытие D5)
# =============================================================================
# Идемпотентно: повторный запуск не создаёт дублей.
#
# Источник параметров — secrets/staff_lyurov2.conf (вне Git). Файл в репозитории
# хранит ПЛЕЙСХОЛДЕРЫ: ключи и endpoint работы подставляются при применении
# (см. блок «Применение» внизу). Не заполнять их в репозитории руками.
#
# ПОЧЕМУ НЕ policy 20/21. После перехода на Вариант B (router/50) диапазоны
# 10.0.0.0/8 и 172.16.0.0/12 лежат в policy-exempt, и правило policy 00
# снимает их с маркировки раньше, чем classifier успел бы пометить conn_work.
# Значит рабочий трафик идёт по таблице main — и достаточно обычных маршрутов
# в main через wg-work. Правила policy 20/21 остаются выключенными как память
# о Варианте A; включать их не нужно.
#
# ПОЧЕМУ wg-work В СПИСКЕ WAN. Двух зайцев одним выстрелом:
#   1) defconf masquerade (out-interface-list=WAN) натит LAN-клиентов в адрес
#      туннеля 172.24.0.7 — сторона работы знает только его (их AllowedIPs
#      для нашего пира почти наверняка /32), пакеты с 192.168.88.x она бы
#      молча выбросила;
#   2) defconf «drop all from WAN not DSTNATed» закрывает НОВЫЕ входящие
#      соединения ИЗ рабочей сети в дом. Ответы (established/related) ходят.
#
# ПОЧЕМУ В allowed-address НЕТ 192.168.0.0/16, хотя работа его выдала.
# Этот диапазон накрывает домашнюю сеть 192.168.88.0/24. Наружу мы его
# в туннель не маршрутизируем, а на вход allowed-address работает фильтром
# по src — оставить его значило бы разрешить рабочей стороне слать пакеты
# от имени домашних устройств. Если у работы найдутся ресурсы в 192.168.x —
# добавить их точечными подсетями, не всем /16.
# =============================================================================

:local wgPrivKey "@@WG_WORK_PRIVATE_KEY@@"
:local wgPeerPub "@@WG_WORK_PEER_PUBLIC_KEY@@"
:local wgEndpoint "@@WG_WORK_ENDPOINT_HOST@@"
:local wgEndPort @@WG_WORK_ENDPOINT_PORT@@

# --- 1. Интерфейс (MTU 1400 — из выданного конфига) --------------------------
/interface wireguard
:if ([:len [find where name="wg-work"]] = 0) do={
  add name=wg-work mtu=1400 private-key=$wgPrivKey \
      comment="work: туннель на работу (D5), параметры из secrets/staff_lyurov2.conf"
}

# --- 2. Членство в списке WAN (NAT + защита от входящих, см. шапку) ----------
/interface list member
:if ([:len [find where interface="wg-work" && list="WAN"]] = 0) do={
  add interface=wg-work list=WAN comment="work: masquerade в 172.24.0.7 + drop новых входящих"
}

# --- 3. Пир ------------------------------------------------------------------
/interface wireguard peers
:if ([:len [find where interface="wg-work"]] = 0) do={
  add interface=wg-work public-key=$wgPeerPub \
      endpoint-address=$wgEndpoint endpoint-port=$wgEndPort \
      allowed-address=172.24.0.0/24,10.0.0.0/8,172.16.0.0/12,100.64.0.0/10 \
      persistent-keepalive=28s \
      comment="work: 192.168.0.0/16 из staff-конфига сознательно опущен (пересекается с домом)"
}

# --- 4. Адрес туннеля --------------------------------------------------------
/ip address
:if ([:len [find where interface="wg-work"]] = 0) do={
  add address=172.24.0.7/24 interface=wg-work comment="work: адрес из staff-конфига"
}

# --- 5. Маршруты -------------------------------------------------------------
# main: рабочие подсети уходят в туннель. 10.200.200.0/24 (роуминг wg0) —
# connected /24, он специфичнее и выигрывает у 10.0.0.0/8 автоматически.
# 172.16.0.0/12 дома не используется (проверено /ip address, 2026-08-18).
/ip route
:if ([:len [find where dst-address="10.0.0.0/8" && gateway="wg-work"]] = 0) do={
  add dst-address=10.0.0.0/8 gateway=wg-work \
      comment="work: корпоративная сеть -> wg-work"
}
:if ([:len [find where dst-address="172.16.0.0/12" && gateway="wg-work"]] = 0) do={
  add dst-address=172.16.0.0/12 gateway=wg-work \
      comment="work: корпоративный RFC1918 -> wg-work (дома не занят)"
}
# CGNAT 100.64.0.0/10 (RFC 6598) — третий внутренний диапазон работы (O34):
# console.evo.mosgortrans.org = 100.65.0.81. В выданном AllowedIPs его не было,
# нашлось по факту поломки. Дома диапазон свободен (Tailscale не используется).
:if ([:len [find where dst-address="100.64.0.0/10" && gateway="wg-work"]] = 0) do={
  add dst-address=100.64.0.0/10 gateway=wg-work \
      comment="work: CGNAT-диапазон работы (O34) -> wg-work"
}
/ip firewall address-list
:if ([:len [find where list="policy-exempt" && address="100.64.0.0/10"]] = 0) do={
  add list=policy-exempt address=100.64.0.0/10 \
      comment="policy: never route via policy tables (work CGNAT, O34)"
}

# table_work получает обещанный в router/10 default — на будущее. Сейчас в неё
# ничего не маркируется (см. шапку), маршрут спит до чьей-нибудь маркировки.
:if ([:len [find where routing-table="table_work" && gateway="wg-work"]] = 0) do={
  add dst-address=0.0.0.0/0 gateway=wg-work routing-table=table_work distance=1 \
      comment="table_work: work -> wg-work (пока не используется, Вариант B)"
}

# --- 6. MSS clamp ------------------------------------------------------------
# MTU туннеля 1400, а PMTUD в корпоративных сетях традиционно мёртв (ICMP
# режут). Без клампа TCP-сессии «подвисают на больших ответах». SYN — первый
# пакет соединения, он всегда проходит mangle до включения fasttrack-offload.
/ip firewall mangle
:if ([:len [find where comment~"^work: MSS"]] = 0) do={
  add chain=forward action=change-mss new-mss=clamp-to-pmtu passthrough=yes \
      protocol=tcp tcp-flags=syn out-interface=wg-work \
      comment="work: MSS clamp наружу (MTU 1400)"
  add chain=forward action=change-mss new-mss=clamp-to-pmtu passthrough=yes \
      protocol=tcp tcp-flags=syn in-interface=wg-work \
      comment="work: MSS clamp внутрь (MTU 1400)"
}

# =============================================================================
# Применение (с ноутбука, ключи подставляются из secrets/ и в Git не попадают):
#
#   ./router/apply-wg-work.sh
#
# Проверка:
#   /interface wireguard peers print detail   -> last-handshake растёт от нуля
#   /ping 172.24.0.1 count=3                  -> шлюз туннеля отвечает
#   /ping 10.199.0.2 count=3                  -> рабочий DNS отвечает
# С LAN-клиента:
#   dig @10.199.0.2 mosgortrans.lan           -> внутренняя зона резолвится
#
# Откат:
#   /ip route remove [find where gateway="wg-work"]
#   /ip firewall mangle remove [find where comment~"^work: MSS"]
#   /interface list member remove [find where interface="wg-work"]
#   /ip address remove [find where interface="wg-work"]
#   /interface wireguard remove [find where name="wg-work"]
# =============================================================================
