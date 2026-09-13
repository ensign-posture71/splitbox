# =============================================================================
# 16 — Роуминговые пиры wg0: устройства владельца на постоянном туннеле домой
# =============================================================================
# Идемпотентно. Здесь только ПУБЛИЧНЫЕ ключи — приватные лежат в клиентских
# конфигах secrets/wg-home-*.conf (вне Git) и на самих устройствах.
#
# Схема (стратегия от 2026-08-21, D24): устройства держат WG-туннель домой
# 100% времени вне дома (On-Demand в приложении WireGuard, исключение —
# домашний SSID). AllowedIPs клиента = 0.0.0.0/0,::/0; дома трафик получает
# обычный policy-routing: wg0 в списке LAN -> catch-all -> sing-box,
# рабочие подсети -> policy-exempt -> main -> wg-work.
#
# Endpoint клиентов — DDNS-имя IP Cloud (92f109fd8555.sn.mynetname.net),
# включён 2026-08-21: WAN-адрес выдан DHCP провайдера и может смениться (O8).
#
# Наследство: пиры client1/2/3 (10.200.200.2-4) существовали до проекта (O4).
# client1 активно используется неизвестным устройством — инвентаризация
# за владельцем; client2/3 без единого байта, кандидаты на удаление.
# =============================================================================

/interface wireguard peers
:if ([:len [find where interface="wg0" && public-key="gSrM6T6IzndfojAF2eIKCiF3Jk7bgORkopN2UXXVFwo="]] = 0) do={
  add interface=wg0 name="mac-leo" \
      public-key="gSrM6T6IzndfojAF2eIKCiF3Jk7bgORkopN2UXXVFwo=" \
      allowed-address=10.200.200.5/32 \
      comment="roaming: MacBook владельца, конфиг secrets/wg-home-mac.conf (D24)"
}
:if ([:len [find where interface="wg0" && public-key="kBs0TwN6/w5c7+XJabCpfoQ7tHQSWV6l0GRu/xCdh1U="]] = 0) do={
  add interface=wg0 name="iphone-leo" \
      public-key="kBs0TwN6/w5c7+XJabCpfoQ7tHQSWV6l0GRu/xCdh1U=" \
      allowed-address=10.200.200.6/32 \
      comment="roaming: iPhone владельца, конфиг secrets/wg-home-iphone.conf (D24)"
}
:if ([:len [find where interface="wg0" && public-key="rxjHRyxTQh4XaGBZRZW/M1W6d8FnL5gHsCR7DYe23D8="]] = 0) do={
  add interface=wg0 name="ipad" \
      public-key="rxjHRyxTQh4XaGBZRZW/M1W6d8FnL5gHsCR7DYe23D8=" \
      allowed-address=10.200.200.7/32 \
      comment="roaming: планшет, конфиг secrets/wg-home-ipad.conf (D24)"
}
# Телефон жены заведён ПОЛНЫМ пиром (как устройства владельца) по прямому
# запросу «аналогично телефону» 2026-08-26 — не гостевым, как отец (D26).
# Перевод в гостевой уровень = добавить 10.200.200.8 в address-list wg-guest.
:if ([:len [find where interface="wg0" && public-key="fJyw+EQsBMMxYDVL4FT/9g2rg426eNOo4ZMfiGcFcT0="]] = 0) do={
  add interface=wg0 name="iphone-wife" \
      public-key="fJyw+EQsBMMxYDVL4FT/9g2rg426eNOo4ZMfiGcFcT0=" \
      allowed-address=10.200.200.8/32 \
      comment="roaming: телефон жены, конфиг secrets/wg-home-wife.conf (D24)"
}

# =============================================================================
# Гостевой уровень (D26): туннель домой БЕЗ доступа к домашней сети и работе
# =============================================================================
# Для устройств родственников: интернет через дом (весь policy-routing
# sing-box работает), но firewall отрезает RFC1918+CGNAT — домашнюю сеть,
# рабочие подсети, других WG-клиентов. Единственное исключение — DNS
# к AdGuard: без него гостю нечем резолвить (и он получает блокировки
# рекламы бонусом).
#
# Механика: адрес гостя в списке wg-guest; правила в конце chain=forward —
# до неявного accept, но после defconf-правил. Заблокированные dst не могут
# создать соединение, поэтому established/fasttrack их не спасут.
# В input один drop: гостю от самого роутера не нужно ничего (ICMP
# пропускает defconf-правило выше — ping 10.200.200.1 остаётся для
# диагностики).

/interface wireguard peers
:if ([:len [find where interface="wg0" && public-key="JcwHl5AvVaukdzYwVCjbYdiyoe40QG/vzswjyiyXLGI="]] = 0) do={
  add interface=wg0 name="father" \
      public-key="JcwHl5AvVaukdzYwVCjbYdiyoe40QG/vzswjyiyXLGI=" \
      allowed-address=10.200.200.10/32 \
      comment="roaming-guest: отец, конфиг secrets/wg-home-father.conf (D26)"
}
:if ([:len [find where interface="wg0" && public-key="vUyfMyb+Alw+hJE4grDiBRAjuoLvYNwuBj/cybEhvlw="]] = 0) do={
  add interface=wg0 name="friend1" \
      public-key="vUyfMyb+Alw+hJE4grDiBRAjuoLvYNwuBj/cybEhvlw=" \
      allowed-address=10.200.200.11/32 \
      comment="roaming-guest: друг, устройство 1, конфиг secrets/wg-home-friend1.conf (D26)"
}
:if ([:len [find where interface="wg0" && public-key="vLAIYNrU2bUUE8zRyVDzr3vNIe+qTrZOzo8j0lv/Ijw="]] = 0) do={
  add interface=wg0 name="friend2" \
      public-key="vLAIYNrU2bUUE8zRyVDzr3vNIe+qTrZOzo8j0lv/Ijw=" \
      allowed-address=10.200.200.12/32 \
      comment="roaming-guest: друг, устройство 2, конфиг secrets/wg-home-friend2.conf (D26)"
}
:if ([:len [find where interface="wg0" && public-key="w2uHs+McKJPRDLwY0t2SwRpMCCpnUCxxxkN+KMgPHz8="]] = 0) do={
  add interface=wg0 name="friend-wife" \
      public-key="w2uHs+McKJPRDLwY0t2SwRpMCCpnUCxxxkN+KMgPHz8=" \
      allowed-address=10.200.200.13/32 \
      comment="roaming-guest: жена друга, конфиг secrets/wg-home-friend-wife.conf (D26)"
}

/ip firewall address-list
:foreach a in={"10.200.200.10";"10.200.200.11";"10.200.200.12";"10.200.200.13"} do={
  :if ([:len [find where list="wg-guest" && address=$a]] = 0) do={
    add list=wg-guest address=$a comment="guest: отец, друг и жена друга (D26)"
  }
}
:foreach e in={"10.0.0.0/8"; "172.16.0.0/12"; "192.168.0.0/16"; "100.64.0.0/10"} do={
  :if ([:len [find where list="wg-guest-blocked" && address=$e]] = 0) do={
    add list=wg-guest-blocked address=$e comment="guest: приватные сети закрыты (D26)"
  }
}

/ip firewall filter
:if ([:len [find where comment~"^guest 01"]] = 0) do={
  add chain=forward action=accept protocol=udp dst-address=192.168.88.45 dst-port=53 \
      src-address-list=wg-guest comment="guest 01: DNS к AdGuard — единственная дверь в LAN"
  add chain=forward action=accept protocol=tcp dst-address=192.168.88.45 dst-port=53 \
      src-address-list=wg-guest comment="guest 02: DNS к AdGuard (tcp)"
  add chain=forward action=drop src-address-list=wg-guest \
      dst-address-list=wg-guest-blocked \
      comment="guest 03: приватные сети и работа закрыты"
  add chain=input action=drop src-address-list=wg-guest \
      comment="guest 04: к самому роутеру нельзя (ICMP пропущен defconf выше)"
}

# =============================================================================
# Уровень «без работы» (D27): свой доступ, закрыты только рабочие сети
# =============================================================================
# АДРЕСНЫЙ ПЛАН wg0 (O36): .2-.4 наследство (client1-3); .5-.9 свои
# устройства (.5 Mac, .6 iPhone, .7 планшет, .8 телефон жены); .10-.19
# гостевой уровень (.10 отец, .11-.13 друзья); .20-.29 уровень «без работы»
# (.20 машина). Перед выдачей адреса — свериться с этим планом И с живыми
# списками роутера: машина сначала получила .11 (занятый гостем friend1)
# и молча попала под гостевые правила (см. D27).
#
# Для устройств владельца, которым нечего делать на работе (машина).
# Дом, роуминговые пиры и весь policy-routing sing-box — как у своих;
# drop только на рабочие диапазоны. Исключение выше дропа: 10.200.200.0/24
# лежит внутри 10.0.0.0/8 — без accept машина потеряла бы других пиров.

/interface wireguard peers
:if ([:len [find where interface="wg0" && public-key="d2oWduECo35+EdNjtrNF0qNBlQsXgTJijOOOqh24Az4="]] = 0) do={
  add interface=wg0 name="car" \
      public-key="d2oWduECo35+EdNjtrNF0qNBlQsXgTJijOOOqh24Az4=" \
      allowed-address=10.200.200.20/32 \
      comment="roaming-nowork: машина, конфиг secrets/wg-home-car.conf (D27)"
}

/ip firewall address-list
:if ([:len [find where list="wg-nowork" && address="10.200.200.20"]] = 0) do={
  add list=wg-nowork address=10.200.200.20 comment="nowork: машина (D27)"
}
:foreach e in={"10.0.0.0/8"; "172.16.0.0/12"; "100.64.0.0/10"} do={
  :if ([:len [find where list="wg-work-nets" && address=$e]] = 0) do={
    add list=wg-work-nets address=$e comment="nowork: рабочие диапазоны (D27)"
  }
}

/ip firewall filter
:if ([:len [find where comment~"^nowork 01"]] = 0) do={
  add chain=forward action=accept src-address-list=wg-nowork dst-address=10.200.200.0/24 \
      comment="nowork 01: роуминговые пиры — не работа"
  add chain=forward action=drop src-address-list=wg-nowork dst-address-list=wg-work-nets \
      comment="nowork 02: рабочие сети закрыты"
}

# Проверка:
#   /interface wireguard peers print where interface="wg0"
#   после подключения устройства: last-handshake растёт от нуля, rx/tx > 0
#   /ip firewall filter print stats where comment~"^guest|^nowork"
# Откат:
#   /interface wireguard peers remove [find where name~"-leo" || name="father"]
#   /ip firewall filter remove [find where comment~"^guest"]
#   /ip firewall address-list remove [find where list~"^wg-guest"]

# =============================================================================
# Уровень «работа + зарубеж, без дома» (D28): начальник
# =============================================================================
# Диапазон .30-.39 (адресный план O36). Доступ: рабочие сети через wg-work,
# интернет и «зарубеж» через sing-box — а ВЕСЬ 192.168.0.0/16 (дом) и другие
# WG-клиенты закрыты. DNS у клиентов РАБОЧИЙ (10.199.0.2/.3, зашит в конфиг):
# домашний AdGuard в запрещённой сети. Чтобы эти запросы прошли dns-policy
# (wg-work в списке WAN!), адреса заведены в dns-allowed — по смыслу это
# и есть «прямой DNS разрешён».
# ВНИМАНИЕ: рабочая сторона видит начальника как 172.24.0.7 — staff-туннель
# владельца. Осознанное следствие схемы (D28).

/interface wireguard peers
:if ([:len [find where interface="wg0" && public-key="HPz6Qg2YvyfFEKj5iwR6Bo4N5/Mqk9S/JoZfykeDS1M="]] = 0) do={
  add interface=wg0 name="boss1" \
      public-key="HPz6Qg2YvyfFEKj5iwR6Bo4N5/Mqk9S/JoZfykeDS1M=" \
      allowed-address=10.200.200.30/32 \
      comment="roaming-worknet: начальник, устройство 1, secrets/wg-home-boss1.conf (D28)"
}
:if ([:len [find where interface="wg0" && public-key="feRsKkgyFLkyKVxkdROkTelEOZvDOvGEbK3FTjCb6G4="]] = 0) do={
  add interface=wg0 name="boss2" \
      public-key="feRsKkgyFLkyKVxkdROkTelEOZvDOvGEbK3FTjCb6G4=" \
      allowed-address=10.200.200.31/32 \
      comment="roaming-worknet: начальник, устройство 2, secrets/wg-home-boss2.conf (D28)"
}

/ip firewall address-list
:foreach a in={"10.200.200.30";"10.200.200.31"} do={
  :if ([:len [find where list="wg-worknet" && address=$a]] = 0) do={
    add list=wg-worknet address=$a comment="worknet: начальник (D28)"
  }
}
:if ([:len [find where list="wg-home-nets" && address="192.168.0.0/16"]] = 0) do={
  add list=wg-home-nets address="192.168.0.0/16" comment="worknet: дом закрыт целиком (D28)"
}

/ip firewall filter
:if ([:len [find where comment~"^worknet 01"]] = 0) do={
  add chain=forward action=drop src-address-list=wg-worknet dst-address=10.200.200.0/24 \
      comment="worknet 01: другие WG-клиенты закрыты (внутри 10/8, поэтому отдельным правилом)"
  # DNS к AdGuard — единственная дверь в 192.168/16 (D28, ревизия: домашний
  # DNS вместо рабочего). Обязано стоять ВЫШЕ worknet 02, как guest 01/02.
  add chain=forward action=accept src-address-list=wg-worknet dst-address=192.168.88.45 \
      protocol=udp dst-port=53 comment="worknet 00: DNS к AdGuard (единственная дверь в 192.168/16)"
  add chain=forward action=accept src-address-list=wg-worknet dst-address=192.168.88.45 \
      protocol=tcp dst-port=53 comment="worknet 00b: DNS к AdGuard (tcp)"
  add chain=forward action=drop src-address-list=wg-worknet dst-address-list=wg-home-nets \
      comment="worknet 02: дом (192.168.0.0/16) закрыт"
  # ВЫШЕ whitelist-WG-clients: то правило (accept src 10.200.200.0/24)
  # иначе пропустило бы начальника к самому роутеру раньше нашего drop (O37).
  add chain=input action=drop src-address-list=wg-worknet \
      place-before=[find where comment="whitelist-WG-clients"] \
      comment="worknet 03: к самому роутеру нельзя (выше whitelist-WG-clients!)"
}
