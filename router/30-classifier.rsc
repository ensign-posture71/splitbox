# =============================================================================
# 30 — Классификатор трафика (шаг 1.4) + обязательное исправление fasttrack
# =============================================================================
# Механика по §4.1: mangle mark-connection -> mark-routing, НЕ routing-rules
# (на роутере есть NAT, routing-rules ломают симметрию соединений).
#
# Почему chain=prerouting безопасен для самого роутера: собственный исходящий
# трафик роутера идёт через chain=output, а не prerouting. Правила ниже его
# не видят — известная ловушка v7 (§4.1) обойдена по построению.
#
# ПОРЯДОК ПРАВИЛ ЗНАЧИМ. Правило 00 идёт первым намеренно: 10.200.200.0/24
# (WG-клиенты) лежит внутри 10.0.0.0/8 (work), и без exempt-предохранителя
# роуминговые клиенты уехали бы в рабочий туннель.
# =============================================================================

/ip firewall mangle

# --- 00. Предохранитель: локальные назначения не маркируем вообще ---------
:if ([:len [find where comment~"^policy 00"]] = 0) do={
  add chain=prerouting action=accept dst-address-list=policy-exempt \
      comment="policy 00: local/exempt dst -> без маркировки"
}

# --- 10/11. «За рубеж» -----------------------------------------------------
# mark-connection ставится один раз на новое соединение (дёшево для CPU),
# mark-routing — на каждый пакет соединения, что и даёт симметрию.
:if ([:len [find where comment~"^policy 10"]] = 0) do={
  add chain=prerouting action=mark-connection new-connection-mark=conn_abroad \
      passthrough=yes connection-state=new dst-address-list=abroad \
      in-interface-list=LAN comment="policy 10: abroad -> conn_abroad"
}
:if ([:len [find where comment~"^policy 11"]] = 0) do={
  add chain=prerouting action=mark-routing new-routing-mark=table_vps \
      passthrough=no connection-mark=conn_abroad in-interface-list=LAN \
      comment="policy 11: conn_abroad -> table_vps"
}

# --- 20/21. «На работу» — создаются ВЫКЛЮЧЕННЫМИ ---------------------------
# wg-work не существует (D5/O5). Включить после шага 1.2, одной командой:
#   /ip firewall mangle enable [find where comment~"^policy 2"]
:if ([:len [find where comment~"^policy 20"]] = 0) do={
  add chain=prerouting action=mark-connection new-connection-mark=conn_work \
      passthrough=yes connection-state=new dst-address-list=work \
      in-interface-list=LAN disabled=yes \
      comment="policy 20: work -> conn_work (ждёт wg-work)"
}
:if ([:len [find where comment~"^policy 21"]] = 0) do={
  add chain=prerouting action=mark-routing new-routing-mark=table_work \
      passthrough=no connection-mark=conn_work in-interface-list=LAN disabled=yes \
      comment="policy 21: conn_work -> table_work (ждёт wg-work)"
}

# =============================================================================
# ОБЯЗАТЕЛЬНОЕ: fasttrack (O6)
# =============================================================================
# Fasttrack уводит пакеты мимо conntrack и mangle. Без этого исключения
# помечается только первый пакет соединения, остальные летят мимо
# table_vps/table_work — классификатор выше становится бесполезен.
#
# connection-mark=no-mark оставляет fasttrack всему немаркированному трафику
# (то есть подавляющему большинству — direct/RU), сохраняя разгрузку CPU
# на слабом hAP ac² (F1). В policy-таблицы уходит только помеченное.
# =============================================================================

/ip firewall filter
set [find where chain="forward" && action="fasttrack-connection"] \
    connection-mark=no-mark \
    comment="defconf: fasttrack (только немаркированные — policy-safe, O6)"

# --- in-interface-list=LAN покрывает и bridge, и wg0 -------------------------
# wg0 состоит в списке LAN (baseline), поэтому роуминговые клиенты получают
# ту же классификацию, что и домашние устройства: их abroad-трафик тоже уйдёт
# через дом на VM. Если это нежелательно — сузить до in-interface=bridge.
# Открытый вопрос §7.12.
