# ADR-X1 — Перевод клиентского ядра коробки с sing-box на Xray-core

Статус: проект (дизайн-фаза, код не изменён)
Дата: 2026-11-05
Контекст: O51 в `docs/decisions.md`

## Контекст и причина

Серверный Xray начиная с 26.9.8 требует в ClientHello key share `X25519MLKEM768`.
sing-box этот share вырезает (SagerNet/sing-box#4520, на 2026-11-03 не исправлено;
проверены 1.14.4 и 1.15.0-alpha). Временная мера: ядро VPS зафиксировано на
26.6.27, на коробке штатный sing-box 1.12.14, в продукте есть патченная сборка
(`product/docker/singbox/Dockerfile`, build-arg `SINGBOX_IMAGE`) — она handshake
чинит, но не решает транспортную половину (см. ниже).

Патченный sing-box и одиночество в экосистеме снимаются одним решением:
клиентом на коробке становится тот же движок, что и на сервере, — Xray-core.
Дальнейшее обновление VPS выше 26.8.x перестаёт зависеть от апстрима sing-box.

**Ключевое ограничение из O51, которое формирует весь документ.** На нашем
маршруте при сервере 26.10.31 примерно 70 % соединений умирало в течение 10 с
(`REALITY: processed invalid connection ... failed to read client hello`), и
то же показал **официальный клиент Xray 26.10.31**. Значит, замена клиентского
ядра сама по себе не гарантирует подъём сервера выше 26.8.x: не доезжает
большой гибридный ClientHello. Поэтому:

- переход клиента на Xray выполняется при сервере 26.6.27 (совместимо: клиент
  Xray работает с сервером, где ML-KEM не требуется);
- подъём ядра сервера — **отдельная операция после** cutover, со своим
  гейт-тестом (§8, Т-7) и не входит в объём этого решения.

## 1. Цель и границы

**Цель.** Боевая коробка (LXC CT 125 `splitbox`, 192.168.88.9, `/opt/splitbox`)
обслуживает трафик LAN и WireGuard-клиентов движком Xray-core. Подмена — одна
операция (cutover), откат — одна операция, без пересборки образов.

**Меняется:** клиентское ядро контейнера `gateway` (sing-box → xray), рендер
конфига, сбор статистики, часть супервизора, пайплайн применения настроек.

**Не меняется (non-goals):**

- роутер MikroTik, `table_vps`, правила заворачивания — коробка по-прежнему
  принимает весь транзит LAN на 192.168.88.9;
- AdGuard (sidecar, 127.0.0.1:53 в общем netns) — DNS-цепочка вне ядра
  не трогается;
- подписки и их разбор (`subs.py`) — канонический промежуточный формат
  кэша `rendered/backup-outbounds.json` остаётся sing-box-подобным словарём
  (см. В-4), конвертация в формат ядра — дело рендера;
- модель `config.yaml` для пользователя (политики, серверы, устройства) —
  схема пополняется одним служебным полем `engine`;
- веб-интерфейс: экраны, формы, сценарии — кроме явно перечисленной
  деградации статистики (§3);
- серверная сторона VPS (3x-ui, ядро сервера) — не объект этого решения;
- мониторинг Prometheus/Grafana (CT 123) — джобу singbox-экспортера чиним
  отдельным этапом после cutover (§9, вне критического пути).

## 2. Матрица паритета функций

Отображение «сейчас (sing-box 1.12.14) → цель (Xray-core)». Поля Xray
проверены по документации и исходникам XTLS/Xray-core (`infra/conf/xray.go`,
`app/dispatcher/sniffer.go`, `app/dispatcher/default.go`, `main/run.go`).

| # | sing-box (файл/поле) | Xray-core | Паритет |
|---|---|---|---|
| 1 | `inbounds: tproxy` 0.0.0.0:7895 (`template.json`) | inbound `protocol: "tunnel"` (alias `"dokodemo-door"`), `settings: {allowedNetwork: "tcp,udp", followRedirect: true}`, `streamSettings.sockopt.tproxy: "tproxy"`, tag `tproxy-in` | полный |
| 2 | `inbounds: mixed` 127.0.0.1:1080, tag `local-probe` | inbound `protocol: "socks"`, `settings: {auth: "noauth", udp: false}`, тот же порт и tag; socks-вход Xray принимает и HTTP | полный |
| 3 | `route.rules[0]: action: sniff` | `sniffing: {enabled: true, destOverride: ["http","tls","quic"], metadataOnly: false, routeOnly: true}` на **каждом** входе. `routeOnly: true` = семантика sing-box sniff: домен идёт только в маршрутизацию, целевой адрес не перезаписывается | полный |
| 4 | `protocol: dns → action: hijack-dns` | правило `{inboundTag: ["tproxy-in","wg-in"], network: "tcp,udp", port: "53", outboundTag: "dns-out"}` + outbound `protocol: "dns"`; отвечает встроенный DNS-модуль (серверы ниже). Встроенный модуль обслуживает только A/AAAA, что нас устраивает | полный |
| 5 | `ip_is_private: true → direct` | `{ip: ["geoip:private"], outboundTag: "direct"}` | полный |
| 6 | `inbound: ["local-probe"] → own-out` | `{inboundTag: ["local-probe"], balancerTag/outboundTag: own}` | полный |
| 7 | Свои подсети: `ip_cidr: […] → own/fast` | `{ip: [cidr…], …}`, порядок не меняется | полный |
| 8 | Свои домены: `domain` (exact) + `domain_suffix` (`.name`) | Xray `domain:name` покрывает сам домен и все поддомены за одну запись — пары exact+suffix сливаются в `["domain:name"]`. Семантика границы метки та же (`myopenai.com` не совпадёт) | полный, конфиг компактнее |
| 9 | Готовые наборы `rule_set` remote→ srs + `cache_file` | Скачивание переносится из рантайма ядра в рендер: новый модуль `rulesets.py` получает списки сетью заранее, рендер инлайнит их в `routing.rules` (В-1). `cache_file` не нужен — конфиг самодостаточен; кэш списков — файлы в `state/rendered/rulesets/` | семантический, механика иная |
| 10 | Свои серверы: `type: vless, server/port/uuid, flow?`, `tls{server_name, utls.fingerprint, reality{public_key, short_id}}` | `protocol: "vless"`, `settings: {vnext: [{address, port, users: [{id, encryption: "none", flow?}]}]}`, `streamSettings: {security: "reality", realitySettings: {serverName, fingerprint, password, shortId, spiderX?}}`. `password` — нынешнее имя бывшего `publicKey` (Xray переименовал; оба имени принимаются, пишем `password`) | полный |
| 11 | `packet_encoding: "xudp"` | нет поля: XUDP в Xray — нативное поведение VLESS для UDP | снимается без потерь |
| 12 | `domain_resolver: "dns-endpoint"` у outbound'ов и `route.default_domain_resolver` | отдельного поля нет. Эквивалент: верхнеуровневый `dns` + `streamSettings.sockopt.domainStrategy: "UseIPv4"` на VLESS-outbound'ах → адрес сервера резолвит встроенный DNS → AdGuard по TCP (§6). Петли нет: запрос к 127.0.0.1 матчится правилом geoip:private → direct | полный, механика иная; см. ОВ-3 |
| 13 | Резервные серверы из подписки: vless/trojan/ss, transport ws/grpc (`subs.py`) | конвертер `to_xray_outbound()` в `render_xray.py`: trojan→`settings.servers[{address,port,password}]`+tls; ss→`settings.servers[{address,port,method,password}]`; ws→`method: "websocket", wsSettings{path, headers.Host}`; grpc→`method: "grpc", grpcSettings{serviceName}` | полный для поддерживаемых схем |
| 14 | Группы: `type: urltest` (`interval`, `tolerance`, `idle_timeout`, url gstatic 204) | `routing.balancers[]: {tag, selector: [префикс…], strategy: {type: "leastPing"}}` + верхнеуровневый `observatory: {subjectSelector, probeUrl: "https://www.gstatic.com/generate_204", probeInterval: <interval>, enableConcurrency: true}`. **Отличия:** (а) `selector` — префиксный матч тегов, не список → теги групп-скоплены (§5.3); (б) у leastPing **нет аналога `tolerance`** — переключается при любом улучшении; принято как отклонение (протокольная метрика не гласная, дребезг гасится самим фактом измерений раз в `interval`) | полный по функции, частичный по настройке |
| 15 | Группы: `strategy: pinned` → `selector` с `default` | отдельного селектора-указателя в Xray нет. pinned = balancer с `selector: ["<точный тег>"]`; рендер обязан гарантировать префиксную однозначность тегов внутри группы (при коллизии — `RenderError`) | полный |
| 16 | Один участник группы → правило на тег напрямую, без группы | то же: без балансера, рендер-уровень | полный |
| 17 | Пустая группа деградирует в соседнюю (`_rewrite_outbound`) | то же, рендер-уровень | полный |
| 18 | `endpoints: wireguard` userspace, tag `wg-in`, `address [10.99.0.1/24]`, пиры `allowed_ips /32` | inbound `protocol: "wireguard"`, `settings: {secretKey, mtu: 1420 (умолчание), peers: [{publicKey, allowedIPs: ["addr/32"], email}]}`. Userspace, без NET_ADMIN — как у sing-box. `email` пира = имя устройства → счётчики `user>>>` (§3). Ключи wg.py (X25519 base64) формально совместимы (`xray wg` генерирует тот же формат) | полный; версия с поддержкой inbound WG фиксируется на Э1 |
| 19 | BitTorrent-политика пиров: после sniff, `{source_ip_cidr, protocol: ["bittorrent"]} → reject|direct` | `{source: ["addr/32"], protocol: ["bittorrent"], outboundTag: blackhole|direct}`. Детектор bittorrent (TCP «BitTorrent protocol» + uTP ST_SYN) в Xray активен всегда при включённом sniffing — отдельного `destOverride` не существует (проверено по `sniffer.go`/`xray.go`). Порядок правил сохраняется: торрент-правила сразу после входов с sniffing, до dns-hijack — как сейчас | полный |
| 20 | `route.final: direct` | Xray: нет `final`; не совпавшее правила идёт в **первый** outbound → первым ставим `freedom` tag `direct` (`streamSettings.sockopt.domainStrategy: "UseIPv4"`) и **дополнительно** последним правилом явный `{network: "tcp,udp", outboundTag: "direct"}` — намеренно дублируем умолчание явным правилом | полный |
| 21 | `action: reject` | outbound `protocol: "blackhole"`, tag `block` | полный |
| 22 | `dns: servers [{type: tcp, server: 127.0.0.1}], strategy: ipv4_only` | `dns: {servers: ["tcp://127.0.0.1"], queryStrategy: "UseIPv4", tag: "dns-internal"}`. TCP выбран по той же причине, что в sing-box: dual-stack UDP-сокет AdGuard в host-network не отвечал на 127.0.0.1 (комментарий в `template.json`) — Xray `tcp://` повторяет рабочую схему | полный |
| 23 | `experimental.clash_api` 127.0.0.1:9090 | `stats: {}` + `policy.system.stats{Inbound,Outbound}{Uplink,Downlink}: true` + `policy.levels."0".statsUser{Uplink,Downlink}` + `api: {tag: "api", listen: "127.0.0.1:10085", services: ["StatsService"]}` (упрощённый режим с 1.8.12: без ручного inbound и правила) + Python-шим в gateway 127.0.0.1:9551 (§5.4) | частичный — разбор в §3 |
| 24 | `experimental.cache_file` (кэш SRS) | не нужен: списки инлайнятся рендером, кэш — файлы `state/rendered/rulesets/` | снимается |
| 25 | `sing-box check -c` | `xray run -c <file> -test` (exit 0 «Configuration OK», 23 при ошибке; проверено по `main/run.go`) | полный |
| 26 | Супервизор: `sing-box run -c`, watchdog socks5h 1080, backoff, сокет `gateway.sock` | те же обязанности, команда движка и путь конфига зависят от ENGINE (§5.2); watchdog не меняется — probe-вход сохранён на тех же адресе/порту | полный |
| 27 | nftables: базовый + tproxy-слои, ip rule/route | без изменений целиком: tproxy ловит в тот же порт 7895 | полный |
| 28 | Логи: `level: warn` | `log: {loglevel: "warning"}`; access-журнал не включать вовсе (O45: три строки на соединение — недопустимо) | полный |

Известная **принятая разница поведения** (не баг, зафиксировать в тестах):
leastPing без tolerance; DNS-ответы WG/LAN-клиентам из встроенного модуля
(только A/AAAA, остальные типы отбрасываются) — у sing-box hijack-dns
проксировал запрос к AdGuard как есть; практический эффект тот же (клиентам
нужны адреса), отличие не наблюдается на клиентских приложениях.

## 3. Что держится на clash_api и что останется

Точный инвентарь (по коду `product/core/splitbox/`):

| Потребитель clash_api `/connections` | Что даёт сейчас | После Xray |
|---|---|---|
| `stats.py` Collector → SQLite `traffic`/`traffic_hourly`/`hosts` | поминутный трафик: устройство × outbound; «кто куда ходил» по хостам | переписывается на stats API: outbound и user счётчики (§5.4). **Уходит:** поминутная разбивка по LAN-устройствам (у Xray нет source-IP счётчиков для tproxy-входа — только per-inbound агрегат) и таблица `hosts` (истории по сайтам не будет). Таблицы в SQLite не удаляются, старые данные остаются читаемыми; новых строк в `hosts` нет |
| `stats.live_status()` → дашборд | живые соединения, байты up/down total | заменяется: «API жив» + счётчики inbound/outbound + число онлайн-WG-устройств (`user online`) |
| `traffic.py` → страница `/traffic` | живая таблица соединений (IP, хост, правило, классификация torrent/udp) | **функции нет**: у Xray нет аналога `/connections`. Страница при `engine=xray` показывает честную заглушку + онлайн-WG-устройства. Модуль не удаляется (engine=singbox продолжает работать) |
| `exporter.py` → Prometheus :9550 | `singbox_*` метрики по outbound | переписывается на shim (метрики `xray_outbound_...`). **Факт:** в compose exporter-сервиса нет, а `monitoring/prometheus.yml` указывает на остановленный .6 — экспортер де-факто не задеплоен; восстановление/перевод — этап после cutover, не гейт |
| `/connect` (`stats.by_peer` за час) | «пошёл ли трафик из LAN» | на engine=xray признак деградирует до «трафик через tproxy-in есть/нет» (счётчик inbound) |

Что **сохраняется** за счёт Xray stats: байты по каждому outbound
(`outbound>>><tag>>>traffic>>>uplink|downlink` — включая каждый сервер и
направления own/fast/direct), по входам (`inbound>>>tproxy-in|wg-in|local-probe`),
по WG-устройствам (`user>>><email>>>traffic…`, online). Донат направлений,
график «сегодня», суммы за период — переживают переход. Системные графики
(`sysstats.py`, /proc) не зависят от движка.

Email WG-пира: в рендер кладётся `email = peer.name` (человеческое имя),
а `allowedIPs` остаётся адресом — счётчики сразу получают читаемые имена.

## 4. Развилки (альтернативы, выбор, причины)

### В-1. Rule-set'ы: инлайн против geosite.dat

- **Выбрано: инлайн по политике.** Новый модуль `rulesets.py` при рендере
  (и суточном refresh) скачивает выбранные наборы и нормализует в два массива:
  домены (`domain:name`) и CIDR. Рендер сливает по политике: четыре
  сгенерированных правила на наборную часть — `{ip: rs-fast}`, `{ip: rs-own}`,
  `{domain: rs-fast}`, `{domain: rs-own}` (внутри Xray-правила несколько полей
  — это AND, поэтому ip и domain раздельно; слияние по политике не теряет
  поведения, т.к. исход равен политике). Источники (проверено существование):
  `vernette` — `…/json/<name>.json` (декомпилированный sing-box rule-set:
  `rules[].domain/domain_suffix/ip_cidr`; у telegram есть CIDR — они и покрывают
  MTProto); `metacubex` — `…/meta/geo/geosite/<name>.list`, `…/geo/geoip/<name>.list`
  (plain-text). `catalogs/sources.yaml` получает второй набор URL-шаблонов
  (`xray_url`, `xray_geoip_url`), старые `url` для sing-box остаются.
  Кэш: `state/rendered/rulesets/<prefix>-<name>.json`; при недоступной сети —
  последний кэш (семантика `cache_file`, но без GitHub в критическом пути
  старта ядра).
- Отвергнуто: **сборка/скачивание `geosite.dat`/`geoip.dat`** (`ext:file:tag`).
  Причины: (1) в ветке `meta` у MetaCubeX per-category `.dat` больше не
  публикуется — только `.list/.mrs/.yaml`; своей protobuf-сборки нам не нужно;
  (2) geosite-коды категорий не совпадают 1:1 с именами наборов — потребовалась
  бы таблица соответствия; (3) выигрыша нет: списков порядка десятков, конфиг
  остаётся компактным (кроме rkn — см. Р-4).
- Цена выбора: инлайн `vernette:rkn` (~2,3 МБ JSON, ~70 тыс. доменов) — рост
  конфига и времени `xray run -test`; в каталоге rkn default=off, приёмочная
  проверка Э6 включает его замер.

### В-2. Статистика: stats API против деградации против «двух источников»

- **Выбрано: сборщик с двумя источниками, выбор по движку** (`engine-aware`):
  singbox → текущий clash-путь; xray → шим на stats API (§5.4). Это не
  «оба одновременно» (ядер одновременно нет), а один коллектор с двумя
  адаптерами. Деградация §3 принята владельцем как цена перехода и видна в UI.
- Отвергнуто: прямой gRPC-клиент в app (нужны grpcio + сгенерированные
  protobuf-стабы Xray — тяжёлая зависимость ради четырёх счётчиков; шим на
  `xray api statsquery` в gateway покрывает всё тем же python3, который там
  уже есть).
- Отвергнуто: «только счётчики без переписывания коллектора» — тогда ломаются
  дашборд и `/connect`; вариант не принят.

### В-3. WireGuard роуминг: userspace inbound против kernel WG

- **Выбрано: userspace `wireguard` inbound Xray** (п.18 матрицы). Ни одного
  изменения для клиентов: порты, ключи, `.conf` из `wg.py`, DNS=10.99.0.1 —
  всё сохраняется.
- Отвергнуто: kernel-WG (`wg-quick`, интерфейс `wg0` в контейнере + расширение
  tproxy-цепочки на `iifname "wg0"`). Причины: (1) в режиме vps контейнер
  сегодня без `NET_ADMIN` и `/dev/net/tun` — пришлось бы добавлять привилегии
  ради того, что userspace-вход решает без них; (2) трафик WG-клиентов ушёл бы
  в ядерный конвейер (зависимость от модуля хоста LXC); (3) два интерпретатора
  правил вместо одного (nft + xray routing) — хуже диагностика.
- ОВ-1 (открытый вопрос): поведение обращений WG-клиента к самой коробке
  (панель по 10.99.0.1:8443). В userspace схеме обоих движков такой пакет
  попадает в маршрутизацию → `geoip:private` → direct → dial 10.99.0.1,
  которого в ядре нет. Проверить на боевой установке, работает ли это сейчас
  у sing-box; для Xray при необходимости — правило
  `{inboundTag: ["wg-in"], ip: ["10.99.0.1/32"], port: "8443", outboundTag: "panel-out"}`
  с outbound `freedom` + `redirect: "127.0.0.1:8443"` (общий netns). Решение —
  по результату проверки, паритет не хуже текущего состояния.

### В-4. Формат конфигурации продукта и флаг движка

- **Выбрано:** `config.yaml` не меняет структуру; добавляется одно поле
  `engine: singbox|xray` (default `singbox`). Источник истины — переменная
  `ENGINE` в `/opt/splitbox/.env` → пробрасывается compose в gateway, app и
  init; `bootstrap.py` синхронизирует её в `config.yaml` точно так же, как
  сейчас `MODE` → `mode` (см. `bootstrap.py:26`). `SCHEMA_VERSION` не
  поднимается: поле с умолчанием обратно совместимо.
  **Cutover/rollback = переключение одного поля `.env` + пересоздание
  контейнеров** (§7). Откат работает при мёртвой панели и мёртвой вебке:
  зависит только от файла `.env` и локальных образов.
- Отвергнуто: «engine только в config.yaml» — gateway не должен читать YAML
  (в нём нет pydantic/pyyaml по замыслу тонкого образа), а откат через панель
  недопустим как единственный путь (философия fail-open распространяется и
  на саму панель).
- Отвергнуто: отдельный набор compose-файлов (`compose.xray.yaml`) — дубль
  всего стека; env-флаг дешевле и атомарнее.

## 5. Архитектура решения

### 5.1. Новые и изменённые модули `product/`

| Файл | Изменение |
|---|---|
| `core/splitbox/render_xray.py` | **Новый.** `render_config(cfg, backups) -> dict`, `render_json`. Механика шаблона сохраняется (`template.xray.json`, `${NAME}`, ключи `//`, удаление пустых). Динамические части: свои серверы (п.10), конвертер резервных (п.13), группы-балансеры (п.14/15 + групп-скопленные теги, §5.3), инлайн наборов из `rulesets`, torrent-правила, wireguard inbound. Дегдарации групп как у sing-box (пустая→соседняя, обе пустые→RenderError) |
| `core/splitbox/template.xray.json` | **Новый.** Скелет конфига §6 |
| `core/splitbox/rulesets.py` | **Новый.** `ensure_cached(cfg) -> None` (скачать включённые наборы по `xray_url` из `catalogs/sources.yaml`, нормализовать и положить в `state/rendered/rulesets/`; ошибка сети → старый кэш; нет ни сети, ни кэша → RenderError с именем набора) и `load_merged(cfg) -> {policy: {domains:[], ips:[]}}`. Время жизни кэша — до следующего удачного скачивания; TTL контролирует суточный refresh |
| `core/splitbox/model.py` | `Engine` enum + `Config.engine: Engine = Engine.singbox`; `Strategy` без изменений (latency/pinned пытаемся отобразить в §2.14/15) |
| `core/splitbox/apply.py` | Диспетчер по `cfg.engine`: рендер (`render.py` или `render_xray.py`) → файл `rendered/{singbox,xray}.json(.new)` → проверка (`sing-box check` либо `xray run -test`; оба бинаря в app-образе) → `os.replace` → тот же `signal_reload` по сокету. Путь/команда — из таблицы движков в `paths.py` |
| `core/splitbox/paths.py` | `XRAY_LIVE/NEW`, `RULESETS_DIR`, таблица `ENGINES = {"singbox": …, "xray": …}` |
| `core/splitbox/bootstrap.py` | sync `ENGINE` из env → `cfg.engine` (по образцу `MODE`) |
| `core/splitbox/stats.py` | Collector: выбор источника по движку; адаптер xray — опрос шима 9551 (§5.4), дельты счётчиков → те же корзины; `direction()` обновляется под групп-скопленные теги (`own-…`/`fast-…`) |
| `core/splitbox/traffic.py`, шаблон `traffic.html` | инвариант «engine=xray» → заглушка |
| `core/splitbox/exporter.py` | источник shim; имена метрик `xray_*` (чтобы не смешивать ряды) |
| `core/splitbox/api/app.py` | панель: значок движка на «Статус»; команда «Подготовить Xray-конфиг» (рендер+`-test` без смены движка); остальная логика apply не меняется |
| `docker/gateway/gateway.py` | §5.2 |
| `docker/gateway/Dockerfile` | **один образ, два бинаря**: `COPY --from=singbox …/sing-box` и `COPY --from=xray /usr/bin/xray` (образ `ghcr.io/xtls/xray-core:<pin>`, build-arg `XRAY_IMAGE`). Альтернатива «образ splitbox-gateway-xray отдельно» отвергнута: откат не должен требовать пересборки/перескачивания |
| `docker/app/Dockerfile` | добавить тот же xray-бинарь рядом с sing-box (проверка конфигов обоих движков в apply-пайплайне) |
| `compose.yaml`, `compose.lan.yaml` | `ENGINE` в environment gateway/app/init; build-arg `XRAY_IMAGE`; новый том `xray-assets` **не** нужен (инлайн-решение В-1); том `singbox-cache` остаётся для engine=singbox |
| `install.sh` | флаг `--engine xray|singbox` — одна команда cutover/rollback (записывает `.env`, `compose up -d`); без флага поведение прежнее |
| `catalogs/sources.yaml` | поля `xray_url` (+`xray_geoip_url` для metacubex) |
| Тесты | `tests/golden/xray-lan.json`, `xray-vps.json`; `test_render_xray.py` — инварианты порядка правил (свои списки выше наборов; dns-hijack выше private; torrent после входов со sniffing; финальный direct), деградации групп, конвертер резервных; golden прогоняется настоящим `xray run -test` (skip при отсутствии бинаря — по образцу текущих golden) |

### 5.2. Супервизор (`gateway.py`)

- `ENGINE = os.environ.get("ENGINE", "singbox")`; таблица
  `{"singbox": (["sing-box","run","-c",SB_JSON], SB_JSON),
    "xray": (["xray","run","-c",XR_JSON], XR_JSON)}`.
- Всё остальное — как есть: порядок «сначала сеть, потом движок»; tproxy-слой
  только при живом движке; watchdog probe без изменений (`PROBE_PROXY`
  socks5h://127.0.0.1:1080 — вход сохранён); двухфазный fail-open;
  `loop_detected`; сокет: `status` дополнительно сообщает `engine=<…>`.
- Ждущий цикл конфига ждёт файл **своего** движка.
- Новый поток `serve_stats` (только ENGINE=xray): §5.4.

### 5.3. Группы и балансировка в Xray

`selector` балансера матчит **префикс** тегов. Пересечение групп
(признак `in_own` и `in_fast` у одного сервера) префиксом не выразить, поэтому
рендер разворачивает физический сервер в по одному outbound на группу:
участник own → тег `own-<base>`; участник fast → тег `fast-<base>`
(`<base>` — сегодняшний `safe_tag` без префикса). Статистика по префиксам
сходится к направлениям автоматически; `direction()` в stats.py учитывает это.

- latency → `{tag: "own-out", selector: ["own-"], strategy: {type: "leastPing"}}`,
  observatory покрывает `subjectSelector: ["own-","fast-"]`;
- pinned → `selector: ["<grp>-<base>"]` точным тегом; рендер проверяет, что
  тег не является префиксом другого члена группы, иначе `RenderError`;
- один участник → без балансера (п.16).

Побочный эффект: дублированный outbound того же сервера в двух группах —
второй handler на тот же адрес; для VLESS это безсостоятельный объект,
observatory меряет каждый тег отдельно (двойной замер одного сервера —
приемлемо).

### 5.4. Статистика: шим вместо clash_api

- В конфиге Xray: `stats: {}`, `policy.system.stats{Inbound,Outbound}…: true`,
  `policy.levels."0".statsUserUplink/Downlink: true`,
  `api: {tag: "api", listen: "127.0.0.1:10085", services: ["StatsService"]}`
  (упрощённый режим с 1.8.12 — отдельный inbound и правило маршрутизации
  не нужны).
- `docker/gateway/xray_statsd.py` (новый) — 40 строк: HTTP на 127.0.0.1:9551,
  `GET /counters` → `xray api statsquery --server=127.0.0.1:10085` (JSON),
  `GET /online` → соответствующая подкоманда (`xray help api` — точное имя при
  имплементации, кандидаты `cmdOnlineStats/cmdGetAllOnlineUsers`). Запускается
  потоком в `gateway.py` при ENGINE=xray. Gateway остаётся единственным
  владельцем жизненного цикла — шим его часть, а не пятый процесс.
- App: `stats.Collector` при engine=xray опрашивает shim раз в 5 с
  (CLI-вызовы дешёвые; 2 с ни к чему — это уже не живые соединения) и пишет
  приросты в те же таблицы: peer = «wg:<email>» для user-счётчиков
  (соответствие имени через `_resolve_peer` по адресу пира),
  peer = «lan (все)» для `inbound>>>tproxy-in`; outbound = тег без группового
  префикса для читаемости.

### 5.5. Проверка конфигурации перед применением

`apply.py` для engine=xray: запись `rendered/xray.json.new` → `xray run -c
rendered/xray.json.new -test` (бинарь в app-образе, тот же тег, что в
gateway-образе: версии проверки и исполнения обязаны совпадать — по образцу
комментария в `docker/app/Dockerfile`) → `os.replace` → `reload` в сокет.
Порядок наследует донора без изменений: боевая конфигурация заменяется только
после успешной проверки.

## 6. Скелет конфига Xray (template.xray.json)

Без значений секретов; плейсхолдеры `${…}` — как в `template.json`.
Собственный сервер подставляется из модели (`secrets/reality-vps.env` —
источник текущих параметров, в документе не приводится).

```json
{
  "log": {"loglevel": "warning"},
  "stats": {},
  "api": {"tag": "api", "listen": "127.0.0.1:10085", "services": ["StatsService"]},
  "policy": {
    "system": {"statsInboundUplink": true, "statsInboundDownlink": true,
               "statsOutboundUplink": true, "statsOutboundDownlink": true},
    "levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true}}
  },
  "dns": {"servers": ["tcp://127.0.0.1"], "queryStrategy": "UseIPv4",
          "tag": "dns-internal"},
  "observatory": {"subjectSelector": ["own-", "fast-"],
                  "probeUrl": "https://www.gstatic.com/generate_204",
                  "probeInterval": "5m", "enableConcurrency": true},
  "inbounds": [
    {"tag": "tproxy-in", "listen": "0.0.0.0", "port": 7895,
     "protocol": "tunnel",
     "settings": {"allowedNetwork": "tcp,udp", "followRedirect": true},
     "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"],
                  "metadataOnly": false, "routeOnly": true},
     "streamSettings": {"sockopt": {"tproxy": "tproxy"}}},
    {"tag": "local-probe", "listen": "127.0.0.1", "port": 1080,
     "protocol": "socks", "settings": {"auth": "noauth", "udp": false},
     "sniffing": {"enabled": true, "destOverride": ["http", "tls"],
                  "routeOnly": true}},
    {"tag": "wg-in", "listen": "0.0.0.0", "port": 51820,
     "protocol": "wireguard",
     "settings": {"secretKey": "${WG_PRIVATE_KEY}", "peers": "${WG_PEERS}"},
     "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"],
                  "routeOnly": true}}
  ],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom",
     "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}}},
    {"tag": "block", "protocol": "blackhole"},
    {"tag": "dns-out", "protocol": "dns"}
  ],
  "routing": {"domainStrategy": "AsIs",
    "rules": [
      "${TORRENT_RULES}",
      {"inboundTag": ["tproxy-in", "wg-in"], "network": "tcp,udp",
       "port": "53", "outboundTag": "dns-out"},
      {"ip": ["geoip:private"], "outboundTag": "direct"},
      {"inboundTag": ["local-probe"], "balancerTag": "${OWN_TARGET}"},
      {"ip": ["${CIDR_FAST}"], "balancerTag": "fast-out"},
      {"ip": ["${CIDR_OWN}"], "balancerTag": "own-out"},
      {"domain": ["${DOMAINS_FAST_PLAIN}"], "balancerTag": "fast-out"}
    ],
    "balancers": []}
}
```

Порядок правил переносится один в один (dns-hijack выше private — причина та
же: адрес WG-подсети приватный; свои списки выше наборов — D29; fast выше own;
финальное явное правило `{network: "tcp,udp", outboundTag: "direct"}`).
`tproxy-in` рендерится только в режиме lan-gateway; в режиме vps его нет —
как сейчас. Пустые массивы в правилах не допускаются (фильтр как в render.py).

## 7. Cutover в один момент и откат

Подготовка (всё до окна подмены, боевой путь не трогается):

1. Образы собраны и лежат локально: `docker compose build` нового кода
   (`--network=host` при перехвате — грабля O42 действует и здесь).
2. На коробке, в app: «Подготовить Xray-конфиг» → `rendered/xray.json`
   собран из боевой модели + боевого кэша подписок, `xray run -test` зелёный.
3. Лабораторные прогоны §8 Т-1…Т-6 пройдены.
4. В репозитории закоммичен код; на коробке `install.sh` обновлён.

Подмена — одна команда:

```sh
cd /opt/splitbox && sh install.sh --engine xray
```

Она: записывает `ENGINE=xray` в `.env` → `docker compose -f compose.yaml -f
compose.lan.yaml up -d` → пересоздаются gateway и app (env изменился) →
gateway поднимает `xray run -c rendered/xray.json`, ставит обвязку, watchdog
снимает/возвращает tproxy по прежней логике. Окно разрыва = пересоздание
gateway: снятие и установка nft-слоёв + старт процесса, измеренный ориентир
5–15 с (сопоставимо с нынешним «Применить»/перезапуском стека; роутер и его
маршруты не трогаются вообще).

Откат — одна команда: `sh install.sh --engine singbox`. Образ sing-box и
`rendered/singbox.json` нетронуты; возврат тем же окном в 5–15 с. Полный
порядок восстановления после катастрофы остаётся `docs/RESTORE-FROM-BACKUP.md`.

Проверки после подмены (чек-лист):
`sock status` отвечает `engine=xray up`; `health.probe_tunnel` из app — IP
своего VPS; три контрольных запроса LAN-клиентом (own-домен, fast-сервис,
прямой сайт); handshake WG-устройства друга и его DNS; график «сегодня»
растёт; `docker logs gateway` без `Failed to start`.

Замороженный конфликт версий: после cutover «Применить» в панели рендерит
xray-конфиг; `singbox.json` не перегенерируется — он заморожен на момент
подмены, что и даёт честный откат.

## 8. План тестирования до подмены

Лаборатория — контейнер в общем netns стека (`--network container:splitbox-gateway-1`),
свой лаб-конфиг: socks 127.0.0.1:1081, wg-in на 51821/udp, tproxy на 7896,
api 10086, шим отключён. Запуск руками, в compose не входит.

- **Т-1 socks без tproxy.** Через `socks5h://127.0.0.1:1081`: exit-IP = свой
  VPS; 5 контрольных доменов own (Telegram/OpenAI-набор), 5 fast (из каталога),
  5 direct (ya.ru/gosuslugi); UDP: STUN/QUIC-запрос.
  Порог: все запросы успешны, направления — по логу Xray
  (`tproxy-in >> own-…` и т.п.). DNS-hijack здесь не проверяется: правило
  привязано к `tproxy-in`/`wg-in` — его проверяют Т-4 и Т-5.
- **Т-2 резервная группа.** 20 подряд запросов к fast-домену: балансер
  жив, переключения видны; принудительный обрыв текущего лидера (дроп до
  его адреса в лаб-nft) → leastPing уходит на следующего ≤ 2 интервалов
  observatory.
- **Т-3 наборы.** По 3 домена из включённых vernette/metacubex наборов —
  маршрут по правилу набора; неперечисленный домен — direct. Сверка рендера
  с кэшем: поля `full:/domain:` из json-формы vernette, CIDR telegram в ip-правиле.
- **Т-4 WireGuard.** Устройство из приложения WireGuard на лаб-порт 51821
  (копия конфига из панели, смена Endpoint): handshake, DNS через 10.99.0.1,
  own/fast/direct маршруты; устройство с `torrent_policy=block`: magnet/uTP
  обрываются (blackhole виден в логе); `torrent_policy=direct` — идут мимо
  туннеля (виден source-IP дома). Проверить macOS и iOS клиентов.
- **Т-5 tproxy на отдельном устройстве.** Соседняя nft-таблица
  `splitbox-xraylab` (mark 2, route table 101): правило ловит только
  `ip saddr <тест-устройство>/32 → tproxy 127.0.0.1:7896`; на устройстве шлюз
  меняется вручную на 192.168.88.9 (без правок роутера — как «первое
  устройство» в /connect). Полный чек-лист Т-1 по живому транзиту + замеры
  скорости 4 потоками (база сравнения — показатели §9 HANDOFF).
- **Т-6 нагрузочный суточный прогон.** Лаб-инстанс сутки под нагрузкой
  тест-устройства (видео/торрент-легальный/DNS-шум): RSS Xray, CPU,
  утечки сокетов, json-лог (O45/O50 — уровень warning, access выключен).
- **Т-7 (гейт ML-KEM, отдельно от cutover).** После устойчивой работы
  клиента Xray: на VPS поднять ядро ≥ 26.9.8 (песочница 3x-ui или часы
  малой нагрузки), бурст 50 соединений через own с коробки. Порог 50/50.
  Провал → сервер обратно на 26.6.27, исследование транспорта большого
  ClientHello (кандидат № 1 — потеря фрагментов/сегментов на пути: проверить
  MSS-clamp до VPS на коробке, захват на обоих концах). До прохождения Т-7
  правило O51 «не поднимать выше 26.8.x» остаётся в силе.

## 9. Риски, открытые вопросы, вне объёма

Риски:

- **Р-1 (главный).** Отказы большого ClientHello на маршруте к VPS — переносится
  не клиентом (O51: официальный Xray-клиент давал те же 70 %). Выход: гейт Т-7;
  cutover не привязан к подъёму сервера.
- **Р-2.** Молодой userspace WG-inbound: возможны несовместимости клиентов/
  падения под нагрузкой. Митигация: Т-4 на реальных устройствах, откат одной
  командой. Точную минимальную версию фиксируем на Э1 (`xray run -test` по
  golden с wireguard inbound; пин тега в `XRAY_IMAGE`).
- **Р-3.** Деградация статистики (§3): раз владелец принял — делаем видимой
  в UI, не молчим.
- **Р-4.** Инлайн `vernette:rkn` (~70 тыс. доменов): рост времени парса/
  памяти/времени `-test`. Меряется на Э6 при включённом rkn; при неприемлемых
  числах — переход именно этой пары наборов на `ext:…` геофайлы (частичный
  возврат отвергнутой ветки, только для гиганта).
- **Р-5.** Семантика `.list` metacubex (суффикс-домены построчно, возможны
  комментарии/`+.`): нормализатор обязан чистить и сверять с json-формой на
  выборке; расхождение — ошибка рендера, не молчаливый пропуск.
- **Р-6.** Префиксные коллизии тегов в pinned (`fast-nl` / `fast-nl-2`):
  рендер проверяет префиксную однозначность внутри группы, иначе RenderError.
- **Р-7.** Логи: держать `warning`, access-журнал не включать (O45/O50).
  Пределы json-file в compose уже есть.
- **Р-8.** Двойной замер одного сервера observatory’ем при участии в двух
  группах — сетевой шум по расписанию `probeInterval`; цена принята.

Открытые вопросы (ответ влияет на реализацию, не на структуру):

- **ОВ-1.** Работает ли сегодня панель через WG-адрес коробки (10.99.0.1:8443)
  на sing-box? От ответа зависит redirect-outbound в шаблоне (§ В-3).
- **ОВ-2.** Минимальный стабильный тег `ghcr.io/xtls/xray-core` с inbound
  wireguard и с `tunnel`-именем inbound (alias dokodemo-door) — пин после
  проверки на Э1; требование в любом случае «не старше релиза с обоими».
- **ОВ-3.** Имя `password` vs устаревший `publicKey` в `realitySettings`
  закреплённой версии (документация: переименовано, оба принимаются) —
  подтвердить `-test` на golden.
- **ОВ-4.** Точные имена CLI-подкоманд online-статистики (`xray help api`)
  для шима.

Не входит в объём (явно): подъём серверного ядра выше 26.8.x (только гейт Т-7);
роутер и списки на нём; AdGuard; редизайн UI; kernel-WG; IPv6; перевод
мониторинга (починка prometheus-джобы под .9 — отдельной задачей после cutover);
отказ от sing-box-ветки рендера (она остаётся поддерживаемой, пока жив флаг
engine).

## 10. Поэтапный план работ и критерии приёмки

| Этап | Содержание | Приёмка |
|---|---|---|
| Э1. Каркас Xray-конфига | `template.xray.json`, `render_xray.py` (без наборов), конвертер резервных, модель (`Engine`), `paths.ENGINES`, golden xray-vps/lan, `XRAY_IMAGE` пин (ОВ-2) | `pytest` зелёный; golden проходят `xray run -test`; конфиг из боевой `config.yaml` рендерится и принимается `-test` |
| Э2. Наборы | `rulesets.py`, `sources.yaml v2`, инлайн-правила, кэш, суточный refresh | при отключённой сети рендер идёт из кэша; контрольная сверка доменов/CIDR с источниками; `--` rkn: холодный `-test` измерен и записан |
| Э3. Супервизор и apply | диспетчер ENGINE в `gateway.py`, `apply.py`, `bootstrap.py`, Dockerfile'ы (два бинаря), compose env, `install.sh --engine` | на клоне (CT 124 или lima-VM): ENGINE=singbox — поведение бит-в-бит текущему (nft, watchdog, reload по сокету); ENGINE=xray — xray запускается тем же конвейером; откат переключением флага без пересборки |
| Э4. Статистика | шим 9551, адаптер коллектора, дашборд/`live_status`, заглушка `/traffic`, `direction()` под новые теги; exporter переписан (не задеплоен — отдельно) | при ENGINE=xray: донат/графики/суммы растут; WG-устройство видно по имени; `/traffic` честно отказывает; при ENGINE=singbox всё как раньше |
| Э5. Лаборатория | Т-1…Т-6 на боевой коробке параллельно с sing-box | протокол проверок приложен к PR/записи в decisions.md; Т-5 с реального устройства, Т-6 — сутки без аномалий |
| Э6. Cutover | `install.sh --engine xray` на CT 125; чек-лист §7; 48 ч наблюдения | все проверки чек-листа; watchdog ни разу не уводил в fail-open по ложному срабатыванию; метрики направлений сходятся с ожиданием по составу правил |
| Э7. Закрепление | запись O52/D-x в `docs/decisions.md`; обновление HANDOFF/ARCHITECTURE; exporter→Prometheus на .9 (отдельным коммитом); удалять sing-box-рендер НЕ раньше, чем через релиз | репозиторий и коробка синхронны; документы отражают оба движка и флаг переключения |

Параллельно и независимо: план подъёма сервера (Т-7) — владелец решает его
дату отдельно; до тех пор ядро VPS остаётся на 26.6.27 (O51).

## 11. Принятые решения (ADR)

- **D-X1. Клиентское ядро — Xray-core, а не патченный sing-box.** Форк с
  ML-KEM не решает транспортную половину и оставляет нас на одном разработчике;
  собственная поддержка патча хуже, чем движок первого сорта (O51).
  Последствие: зависимость от двух конфигов рендера на время перехода;
  откат — флагом.
- **D-X2. Образ gateway несёт оба бинаря, движок — переменная ENGINE.**
  Откат без сети и без сборки — одинаковая цена cutover и rollback.
- **D-X3. Наборы инлайнятся рендером из текстовых/JSON-источников, а не
  геофайлами и не скачиванием ядром.** Конфиг самодостаточен при мёртвом
  GitHub; плата — рост конфига на rkn (default off) и модуль `rulesets.py`.
- **D-X4. WireGuard остаётся userspace — inbound `wireguard` Xray.**
  Клиентские конфиги, ключи, порты и панель не меняются; привилегии контейнера
  не растут. Kernel-WG отвергнут (NET_ADMIN в режиме vps, раздвоение правил).
- **D-X5. Балансировка — leastPing + observatory; pinned — точным selector.**
  Теги становятся групп-скопленными (`own-*`, `fast-*`), пересечение групп —
  дублированием outbound. Прямого аналога `tolerance` нет — отклонение принято.
- **D-X6. Статистика — stats API через локальный шим в gateway; clash_api
  не портировать.** Принятая деградация: нет живой таблицы соединений, нет
  истории по хостам, нет разбивки LAN по устройствам; остаются счётчики по
  outbound/входам/WG-устройствам и онлайн-лист. gRPC-зависимость в app
  отвергнута.
- **D-X7. Подъём серверного ядра — отдельная операция после Т-7.** Cutover
  клиента не является его условием; до прохождения гейта сервер — 26.6.27.
