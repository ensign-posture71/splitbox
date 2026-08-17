# =============================================================================
# 90 — Гигиена: оживление anti-brute правил (O10.4)
# =============================================================================
# ПРОБЛЕМА 1 (исходная): detect-*/drop-* стоят ПОСЛЕ правила
#   «defconf: drop all not coming from LAN». WAN-трафик до них не доходит —
#   защиты от перебора нет вообще.
#
# ПРОБЛЕМА 2 (найдена при применении, O11): detect-brute стоит ВЫШЕ
#   whitelist-WG-clients, поэтому в список login_attempt попадают доверенные
#   источники. На момент правки там лежал 10.200.200.2 — админский WG-клиент,
#   с которого ведётся управление роутером.
#
#   Наивная перестановка «поднять drop-* выше drop-all» отрезала бы админа
#   от роутера мгновенно и необратимо (удалённо — без шансов на восстановление).
#
# ЦЕЛЕВОЙ ПОРЯДОК — whitelist'ы ПЕРЕД drop'ами, detect'ы перед финальным drop:
#   accept established,related,untracked
#   drop invalid
#   whitelist-LAN            <- доверенные источники выходят из-под подозрения
#   whitelist-WG-clients     <-   ДО того, как их проверят на перебор
#   drop-port-scanners
#   drop-brute
#   accept ICMP / loopback / HermesAI / WireGuard-UDP
#   allow-DNS-LAN / block-DNS-WAN
#   detect-port-scanners     <- ловит только недоверенные источники
#   detect-brute
#   defconf: drop all not coming from LAN
#
# Побочный полезный эффект: ложные срабатывания на своих прекращаются.
#
# Правила ищутся по comment, а не по номеру — номера сдвигаются при каждом
# move, и скрипт с жёсткими номерами однажды переставит не то.
# =============================================================================

/ip firewall filter

:local anchorTop   [find where comment="defconf: accept ICMP"]
:local anchorDrop  [find where comment="defconf: drop all not coming from LAN"]

:if ([:len $anchorTop] = 0 || [:len $anchorDrop] = 0) do={
  :error "Не найдены якорные правила — прервано без изменений"
}

# --- 1. Доверенные источники поднимаются наверх ------------------------------
# Порядок в списке = целевой порядок: каждое move встаёт перед якорем,
# вытесняя предыдущее вверх.
:foreach c in={"whitelist-LAN"; "whitelist-WG-clients"; \
               "drop-port-scanners"; "drop-brute"} do={
  :local r [find where comment=$c]
  :if ([:len $r] > 0) do={
    move $r destination=$anchorTop
    :put ("поднято выше accept-ICMP: " . $c)
  } else={
    :put ("ПРОПУЩЕНО (не найдено): " . $c)
  }
}

# --- 2. Детекторы опускаются к финальному drop -------------------------------
:foreach c in={"detect-port-scanners"; "detect-brute"} do={
  :local r [find where comment=$c]
  :if ([:len $r] > 0) do={
    move $r destination=[find where comment="defconf: drop all not coming from LAN"]
    :put ("опущено к финальному drop: " . $c)
  } else={
    :put ("ПРОПУЩЕНО (не найдено): " . $c)
  }
}

# Проверка после применения:
#   /ip firewall filter print chain=input
#
# Ожидается: whitelist-LAN и whitelist-WG-clients выше drop-brute;
#            detect-* непосредственно перед «drop all not coming from LAN».
