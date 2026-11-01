# Локальный учёт qBittorrent

Агент запускается на хосте qBittorrent и опрашивает только loopback API.
Он не читает названия торрентов, magnet-ссылки, trackers или пути
файлов — только агрегаты и счётчики.

## Установка

```sh
pct exec 104 -- /opt/splitbox/product/qbit_stats/install.sh
```

После установки агент слушает `192.168.88.47:8092`. Splitbox обращается
к нему по bearer-токену из `/opt/splitbox/.env`.

## Прямой маршрут

МикроTik mangle-правило перед catch-all:

```routeros
/ip firewall mangle add chain=prerouting action=accept \\
    src-address=192.168.88.47 in-interface-list=LAN \\
    comment="policy 00d: qbittorrent -> main table (direct) direct"
```

Это гарантирует, что qBittorrent не пойдёт через Splitbox/tunnи.
Оставшиеся mangle-правила сохраняются, NAT для BitTorrent тоже.

## Веб-интерфейс

Если включён прокси `qbit-audit`, qBittorrent Web UI слушает только
`127.0.0.1:8091`, а аудит-прокси остаётся на привычном `8090`.
Логи прокси показывают IP, время и путь; в qBittorrent остаётся обычный
логин. Дальше можно сопоставлять IP с именами устройств по Splitbox.
