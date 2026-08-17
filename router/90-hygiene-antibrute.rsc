# =============================================================================
# 90 — Гигиена: оживление anti-brute правил (O10.4)
# =============================================================================
# Проблема: detect-port-scanners, detect-brute, drop-port-scanners, drop-brute
# стоят ПОСЛЕ правила «defconf: drop all not coming from LAN» в цепочке input.
# WAN-трафик до них не доходит — защиты от перебора сейчас нет вообще.
#
# Решение: поднять их выше drop-правила, в правильном порядке:
#   сначала DROP уже пойманных, потом DETECT новых.
# Иначе нарушитель успевает получить обслуживание в том же цикле.
#
# Правила ищутся по comment, а не по номеру — номера сдвигаются при каждой
# правке, и скрипт с жёсткими номерами однажды переставит не то.
# =============================================================================

/ip firewall filter

:local anchor [find where comment="defconf: drop all not coming from LAN"]
:if ([:len $anchor] = 0) do={
  :error "Не найдено якорное правило 'defconf: drop all not coming from LAN' — прервано"
}

# Порядок перемещения обратный целевому: каждое move ставит правило
# непосредственно перед якорем, вытесняя предыдущее вверх.
:foreach c in={"detect-brute"; "detect-port-scanners"; "drop-brute"; "drop-port-scanners"} do={
  :local r [find where comment=$c]
  :if ([:len $r] > 0) do={
    move $r destination=$anchor
    :put ("перемещено выше drop-правила: " . $c)
  } else={
    :put ("ПРОПУЩЕНО (правило не найдено): " . $c)
  }
}

# Итоговый ожидаемый порядок в input:
#   ... accept established/related/untracked, drop invalid ...
#   drop-port-scanners      (src-address-list=port_scanners)
#   drop-brute              (src-address-list=login_attempt)
#   detect-port-scanners    (add-src-to-address-list, psd)
#   detect-brute            (add-src-to-address-list, dst-port 22,8291,443)
#   defconf: drop all not coming from LAN
#
# Проверка после применения:
#   /ip firewall filter print chain=input
