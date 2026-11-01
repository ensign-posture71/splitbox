# Аудит qBittorrent Web UI

`Caddyfile` поднимает прокси на порту 8090 и пишет JSON-лог
в `/opt/qbittorrent-audit/logs/access.log`. Сам qBittorrent остаётся
на `127.0.0.1:8091`.


## Отчёт

```sh
pct exec 104 -- /opt/qbittorrent-audit/audit_report.py --top 10
```
