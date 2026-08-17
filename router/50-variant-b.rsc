# =============================================================================
# 50 — Переход на Вариант B: роутер перестаёт классифицировать
# =============================================================================
# ПОЧЕМУ. Вариант A требовал заранее знать IP-адреса нужных сервисов.
# За вечер выяснилось, что это неразрешимо в общем случае:
#   * Instagram и YouTube отдают разным запросам разные адреса (O31);
#   * приложения ходят на поддомены, которых нет в списке (i.instagram.com,
#     graph.instagram.com, i.ytimg.com) — каждый обнаруживался по факту поломки;
#   * edge-хосты видео вида rr1---sn-XXXXX.googlevideo.com генерируются
#     под сессию, их нельзя ни перечислить, ни прогреть (D21).
# Каждый механизм (FQDN-записи, DNS-перехват, прогрев, диапазоны) закрывал
# часть случаев и промахивался на остальных.
#
# В Варианте B решение принимает sing-box — по SNI каждого соединения,
# то есть по домену, а не по адресу. Ровно так работает Shadowrocket
# на ноутбуке владельца, и там таких проблем нет.
#
# ЧТО СТАНОВИТСЯ НЕНУЖНЫМ: address-list `abroad`, DNS-статика на 77 доменов,
# прогрев кэша, диапазоны Meta и Google, гонка первого запроса.
# Добавить сервис = дописать строку в sync/abroad-services.list.
#
# ПОЧЕМУ УБИРАЕТСЯ NOTRACK (введён в router/31):
# он был нужен, чтобы «drop invalid» не резал пакеты при асимметрии (O30).
# Но в Варианте B через эти правила идёт ВЕСЬ трафик дома, а untracked-пакеты
# не проходят masquerade. При срабатывании fail-open (маршрут падает на WAN)
# они ушли бы наружу с приватным адресом — то есть интернет лёг бы у всех.
# Вместо notrack ставится точечный accept для invalid только в сторону
# контейнера: conntrack остаётся, NAT работает, fail-open безопасен.
# =============================================================================

# --- 1. Приватные диапазоны никогда не стерятся -----------------------------
# В Варианте B правило-ловушка ловит всё подряд, поэтому предохранитель
# должен покрывать все приватные сети, а не только домашнюю.
/ip firewall address-list
:foreach e in={"10.0.0.0/8"; "172.16.0.0/12"} do={
  :if ([:len [find where list="policy-exempt" && address=$e]] = 0) do={
    add list=policy-exempt address=$e comment="policy: never route via policy tables"
  }
}

# --- 2. Убрать notrack ------------------------------------------------------
/ip firewall raw
remove [find where comment~"^policy raw"]

# --- 3. Разрешить invalid в сторону контейнера ------------------------------
# Роутер видит только половину диалога: ответы контейнер отдаёт клиенту
# напрямую по L2 (O30). Правило узкое — только LAN в сторону bridge.
/ip firewall filter
:if ([:len [find where comment~"^policy B: invalid"]] = 0) do={
  add chain=forward action=accept connection-state=invalid \
      in-interface-list=LAN out-interface=bridge \
      place-before=[find where comment="defconf: drop invalid" && chain="forward"] \
      comment="policy B: invalid в сторону контейнера — обратный путь идёт мимо роутера"
}

# --- 4. Ловушка: весь трафик наружу уходит на контейнер ----------------------
# policy 00 (локальные назначения) и policy 01 (сам шлюз) стоят выше
# и продолжают работать предохранителями.
/ip firewall mangle
:if ([:len [find where comment~"^policy B: catch-all"]] = 0) do={
  add chain=prerouting action=mark-routing new-routing-mark=table_vps \
      passthrough=no in-interface-list=LAN \
      place-before=[find where comment~"^policy 12"] \
      comment="policy B: catch-all -> table_vps (решение принимает sing-box)"
}
# Прежнее правило по address-list выключается, но не удаляется — откат.
:foreach r in=[/ip firewall mangle find where comment~"^policy 12"] do={
  /ip firewall mangle set $r disabled=yes
}

# --- 5. Отключить прогрев — он больше не нужен ------------------------------
# Заодно исчезает самая громкая аномалия из разбора заметности (D20).
/system scheduler
remove [find where name="abroad-warmup"]

# Проверка:
#   /ip firewall mangle print stats where !dynamic
#   /ip firewall filter print stats where comment~"policy B"
# Откат:
#   /ip firewall mangle remove [find where comment~"^policy B"]
#   /ip firewall mangle enable [find where comment~"^policy 12"]
