# =============================================================================
# 40 — Принудительный DNS через роутер (§7.8, условие работы D19)
# =============================================================================
# Схема D19 держится на том, что клиенты резолвят через роутер: он кладёт
# в address-list `abroad` ровно те адреса, которые сам же и отдал.
# Устройство, ходящее по DoH/DoT мимо роутера, получает адрес, которого
# в списке нет, и его трафик молча уходит напрямую.
# Наблюдалось вживую: 192.168.88.4 ходит на 8.8.8.8:853 (DoT), Mac владельца
# резолвит через Shadowrocket (O27).
#
# Поэтому §7.8 здесь перестаёт быть гигиеной и становится условием
# работоспособности.
#
# ⚠️ ТРИ АДРЕСА ОБЯЗАНЫ СОХРАНИТЬ ПРЯМОЙ ДОСТУП, иначе ломается всё:
#   192.168.88.1  — сам роутер (его трафик идёт через chain=output и этими
#                   правилами не затрагивается, внесён для полноты картины);
#   192.168.88.45 — AdGuard, ему нужен выход на свои DoH-апстримы;
#   192.168.88.6  — sing-box, он резолвит адрес VPS собственным резолвером
#                   (8.8.8.8/9.9.9.9, см. O22) — без этого туннель не встанет.
#
# Запросы клиентов К РОУТЕРУ идут в chain=input и правилами ниже не задеты:
# фильтруется только трафик НАРУЖУ.
# =============================================================================

/ip firewall address-list
:foreach a in={"192.168.88.1";"192.168.88.45";"192.168.88.6"} do={
  :if ([:len [find where list="dns-allowed" && address=$a]] = 0) do={
    add list=dns-allowed address=$a comment="dns-policy: прямой DNS разрешён"
  }
}

# --- Известные публичные DoH-серверы ----------------------------------------
# DoH прячется в обычном 443, поэтому по порту его не отличить — только
# по адресам. Список принципиально неполон: он закрывает то, чем реально
# пользуются устройства и браузеры по умолчанию, а не все DoH на свете.
:foreach a in={"1.1.1.1";"1.0.0.1";"8.8.8.8";"8.8.4.4";"9.9.9.9";"149.112.112.112"; \
               "94.140.14.14";"94.140.15.15";"45.90.28.0/24";"45.90.30.0/24"; \
               "208.67.222.222";"208.67.220.220";"76.76.2.0/24";"76.76.19.19"} do={
  :if ([:len [find where list="doh-servers" && address=$a]] = 0) do={
    add list=doh-servers address=$a comment="dns-policy: публичный DoH"
  }
}

/ip firewall filter

# Правила ставятся ВЫШЕ fasttrack и accept-established намеренно: иначе уже
# установленные DoT-сессии продолжали бы жить, а нам нужно их оборвать.
:local anchor [find where comment="defconf: fasttrack"]
:if ([:len $anchor] = 0) do={
  :set anchor [find where action="fasttrack-connection" && chain="forward"]
}

:if ([:len [find where comment~"^dns-policy: plain"]] = 0) do={
  add chain=forward action=drop protocol=udp dst-port=53 \
      in-interface-list=LAN out-interface-list=WAN \
      src-address-list=!dns-allowed place-before=$anchor \
      comment="dns-policy: plain DNS наружу запрещён (udp)"
  add chain=forward action=drop protocol=tcp dst-port=53 \
      in-interface-list=LAN out-interface-list=WAN \
      src-address-list=!dns-allowed place-before=$anchor \
      comment="dns-policy: plain DNS наружу запрещён (tcp)"
}

:if ([:len [find where comment~"^dns-policy: DoT"]] = 0) do={
  add chain=forward action=drop protocol=tcp dst-port=853 \
      in-interface-list=LAN src-address-list=!dns-allowed place-before=$anchor \
      comment="dns-policy: DoT запрещён (tcp/853)"
  add chain=forward action=drop protocol=udp dst-port=853 \
      in-interface-list=LAN src-address-list=!dns-allowed place-before=$anchor \
      comment="dns-policy: DoT запрещён (udp/853)"
}

:if ([:len [find where comment~"^dns-policy: DoH"]] = 0) do={
  add chain=forward action=drop protocol=tcp dst-port=443 \
      in-interface-list=LAN dst-address-list=doh-servers \
      src-address-list=!dns-allowed place-before=$anchor \
      comment="dns-policy: DoH к известным серверам запрещён"
}

# --- Canary-домен: выключает DoH в Firefox штатным способом -----------------
# Firefox проверяет use-application-dns.net; NXDOMAIN означает «в этой сети
# DoH включать не надо». Это единственный способ, который браузер уважает
# добровольно, без блокировок по адресам.
/ip dns static
:if ([:len [find where name="use-application-dns.net"]] = 0) do={
  add name=use-application-dns.net type=NXDOMAIN comment="dns-policy: canary для Firefox"
}

# Проверка после применения:
#   /ip firewall filter print stats where comment~"^dns-policy"
# Растущие счётчики показывают, какие устройства пытались ходить мимо.
