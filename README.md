# Splitbox — умный туннель в коробке

Контейнерный стек «под ключ» для людей, которые ничего не понимают в VPN:
подписка VLESS + WireGuard для устройств + блокировка рекламы + веб-панель.
Наследник домашнего проекта Mikrotik-vpn (см. `../docs/`), упакованный так,
чтобы ставиться одной командой без Mikrotik и Proxmox.

## Что внутри

| Сервис | Роль |
|---|---|
| `gateway` | sing-box: WireGuard-endpoint для устройств, маршрутизация по SNI (свой сервер / группа автовыбора / напрямую), tproxy-перехват LAN в режиме шлюза; супервизор с fail-open-watchdog |
| `adguard` | AdGuard Home: DNS + блокировка рекламы для всех клиентов |
| `app` | веб-панель: онбординг-мастер, каталог сервисов, устройства с QR, подписки, свои списки |

Все сервисы живут в одном сетевом пространстве (`network_mode:
service:gateway`) — общий 127.0.0.1, наружу торчат только WireGuard (UDP)
и вебка.

## Установка на VPS (режим vps)

```bash
curl -fsSL https://raw.githubusercontent.com/CHANGEME/splitbox/master/product/install.sh | sudo sh
```

Инсталлер поставит docker, запустит стек и напечатает ссылку на мастер
настройки (с одноразовым токеном). Дальше — вставить ссылку подписки,
отсканировать QR приложением WireGuard, готово.

В этом режиме весь «прочий» трафик выходит с адреса VPS. «Российские сайты
как из дома» — только в режиме домашнего шлюза.

## Установка дома (режим lan-gateway)

На мини-ПК/Raspberry Pi с docker:

```bash
git clone https://github.com/CHANGEME/splitbox /opt/splitbox
cd /opt/splitbox/product
cp .env.example .env          # MODE=lan-gateway
docker compose -f compose.yaml -f compose.lan.yaml up -d
```

Затем в роутере: DHCP-gateway и DNS → адрес коробки. При падении туннеля
коробка сама снимает перехват — сеть продолжает работать напрямую
(fail-open, проверено учениями: перехват снимается через ~60 с после
обрыва и возвращается сам после починки). При падении самой коробки
верните DHCP обратно.

Требования: ядро с nftables и tproxy (обычный Debian/Ubuntu/Raspberry Pi OS
подходит; Synology — нет, там доступен только режим vps) и **rootful
docker** — в rootless-режиме контейнер не может ставить `ip rule` и nft
даже с NET_ADMIN. Инсталлер сам освобождает порт 53 от systemd-resolved;
при ручной установке это нужно сделать до запуска стека.

## Разработка

```bash
cd product/core
python3 -m venv .venv && .venv/bin/pip install -e ".[api,dev]"
.venv/bin/python -m pytest            # 52 теста, golden-конфиги
SPLITBOX_STATE=/tmp/sb .venv/bin/uvicorn splitbox.api.app:app --reload
```

Golden-конфиги (`core/tests/golden/`) проверяются настоящим `sing-box
check` — при изменении рендера дифф виден в git.

Локальный стенд: `docker compose up -d --build`, вебка на
http://localhost:8443. Правки кода без пересборки образа — оверлей
`compose.dev.yaml` (монтирует пакет поверх site-packages). Проверка
WG-пути без телефона — sing-box на хосте как клиент (endpoint wireguard
на 127.0.0.1:51820, ключи пира из `/devices/{id}/conf`).

**Стенд для lan-режима — только настоящее ядро Linux.** Docker Desktop
не годится: в его linuxkit-ядре nft-правило `tproxy` считает пакеты, но
не доставляет их сокету (проверено голым `IP_TRANSPARENT`-листенером).
Рабочий стенд — Lima:

```bash
limactl start --name=splitbox template://docker
limactl shell splitbox -- sudo sh -c "systemctl unmask docker containerd; systemctl start containerd docker"
docker save splitbox-app splitbox-gateway adguard/adguardhome:v0.107.52 | limactl shell splitbox -- sudo docker load
limactl shell splitbox -- sudo sh -c "cd $PWD && MODE=lan-gateway docker compose -f compose.yaml -f compose.lan.yaml -f compose.dev.yaml up -d --no-build"
```

Rootful docker обязателен: в rootless-режиме `ip rule` и nft недоступны
даже с NET_ADMIN.

## Архитектура и решения

Журнал решений и грабель домашнего проекта-донора: `../docs/decisions.md`
(D1–D26, O1–O35). Ключевое, что перенесено в код коробки:

* **fail-open**: `final: direct` в маршрутизации; сломанный туннель никогда
  не оставляет людей без интернета; kill-switch отсутствует намеренно;
* **применение конфига**: render → `sing-box check` → атомарный replace →
  reload; опечатка не роняет туннель;
* **проверка боевым путём**: health-check ходит наружу через туннель,
  а не смотрит на процесс (`local-probe` + безусловное правило);
* **обвязка и sing-box в одном супервизоре**: их рассинхронизация в доноре
  стоила петли маршрутизации;
* **HWID на подписку**: генерируется один раз, иначе панель исчерпает
  слоты устройств;
* **фильтры подписки**: заглушки, узлы внутри РФ и профили «LTE обход»
  не попадают в группу автовыбора.
