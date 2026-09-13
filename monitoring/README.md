# Мониторинг (D25)

Живёт в LXC **CT 123 `monitoring`** на `hp`, адрес `192.168.88.7`.
Доступ к Grafana: `http://192.168.88.7:3000`, логин/пароль в
`secrets/monitoring.env`. Домашний дашборд — **«VPN Overview»**.

## Состав

| Что | Где | Порт |
|---|---|---|
| Grafana 13 (apt.grafana.com) | CT 123 | 3000 |
| Prometheus (Debian, retention 180d) | CT 123 | 9090 |
| mktxp — экспортер MikroTik | CT 123 | 49090 |
| adguard-exporter (znandev) | CT 123 | 9617 |
| node_exporter | CT 123, singbox-gw, hp | 9100 |
| prometheus-pve-exporter (существовал) | CT 102, `.61` | 9221 |
| singbox-exporter (свой) | singbox-gw | 9550 |

## Экспортер sing-box

`vm/container/singbox-exporter.py` + `.service` — опрашивает clash_api
(`127.0.0.1:9090`, включён в шаблоне конфига) и считает байты по каждому
outbound. Подробности в шапке скрипта. v2ray_api не вариант — официальная
сборка sing-box без него.

## Роутер

Пользователь `mktxp` (группа `monitoring`, политика `read,api`), API-сервис
8728 открыт только для `192.168.88.7`. Пароль в `secrets/monitoring.env`.
В mktxp.conf ключ пиров называется `wireguard_peers`, метрики —
`mktxp_peer_rx_total`/`mktxp_peer_tx_total`/`mktxp_last_handshake`
(без слова wireguard в имени).

## Файлы

- `vpn-overview.json` — сводный дашборд (провижен из
  `/var/lib/grafana/dashboards/` на CT 123)
- `prometheus.yml` — копия боевого конфига Prometheus
- Импортированные дашборды: 1860 (Node Exporter Full), 13679 (MKTXP),
  10347 (Proxmox)

## Грабли

- `grafana-cli admin reset-admin-password` без `GF_PATHS_DATA` правит
  **не ту** базу (homepath, а не `/var/lib/grafana`) и молча «успешен».
- После неудачных логинов Grafana блокирует учётку: чистить
  `DELETE FROM login_attempt;` в `grafana.db` при остановленном сервере.
- Панель «Рукопожатие» исключает мёртвые `client2/3` фильтром
  `name!~"client[23]"` — у них handshake = 0 и они всегда красные.
