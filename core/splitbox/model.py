"""Модель state/config.yaml — единственного источника истины коробки.

Из этой модели рендерятся все производные артефакты: конфиг sing-box,
клиентские конфиги WireGuard, bootstrap AdGuard. Файл редактируется только
через API; формат — YAML, потому что он диффабелен, бэкапится копированием
одного файла и восстанавливается руками при мёртвой вебке.
"""
from __future__ import annotations

import ipaddress
import re
import secrets
import uuid
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = 1


class _Model(BaseModel):
    """Общая база: проверка не только при создании, но и при присваивании.

    Без неё некорректное значение из формы («пять минут» вместо «5m»)
    молча ложилось в поле, попадало в config.yaml — и панель переставала
    открываться вовсе, потому что при следующем чтении файл уже не
    проходил валидацию. Теперь ошибка возникает до записи и показывается
    пользователю.
    """

    model_config = ConfigDict(validate_assignment=True)


class Mode(str, Enum):
    """Режим коробки. vps — вход только через WireGuard; lan_gateway —
    дополнительно tproxy-перехват всего LAN (коробка = default gateway)."""

    vps = "vps"
    lan_gateway = "lan-gateway"


class WorkMode(str, Enum):
    """Режим работы в терминах пользователя — не путать с `mode`, который
    описывает развёртывание (tproxy и host-сеть задаются установщиком).

    lan_only — коробка обслуживает только локальную сеть; внешний адрес
               не нужен, наружу ничего публиковать не надо;
    full     — плюс устройства извне через WireGuard: телефон в поездке,
               ноутбук в кафе. Нужен внешний адрес и проброс порта.
    """

    lan_only = "lan-only"
    full = "full"


class Policy(str, Enum):
    """Куда идёт трафик сервиса.

    off  — напрямую, мимо туннеля;
    own  — только свой сервер (чужие серверы из подписки видят весь
           проходящий трафик, поэтому попадание туда — осознанное решение);
    fast — группа автовыбора: свой + резервные, побеждает самый быстрый.
    """

    off = "off"
    own = "own"
    fast = "fast"


class Admin(_Model):
    """Доступ к вебке. Пароль хранится как scrypt-хэш (splitbox.auth)."""

    password_hash: str = ""          # пусто = онбординг ещё не пройден
    session_secret: str = Field(default_factory=lambda: secrets.token_hex(32))


class OwnServer(_Model):
    """Свой сервер — доверенный выход. Задаётся либо ссылкой vless://,
    либо развёрнутыми полями (Reality). Ссылка разбирается при добавлении
    и раскладывается в поля — храним уже разобранное, чтобы рендер не
    зависел от парсера."""

    name: str
    server: str
    server_port: int = 443
    uuid: str
    flow: str = ""                   # НЕ выставлять, если сервер его не ждёт (D10)
    sni: str = ""
    fingerprint: str = "chrome"
    reality_public_key: str = ""
    reality_short_id: str = ""
    enabled: bool = True
    # В какие группы входит сервер. Свой сервер по умолчанию и «доверенный
    # выход», и участник группы скорости — если он окажется быстрее чужих,
    # трафик останется на нём.
    in_own: bool = True
    in_fast: bool = True

    @field_validator("server")
    @classmethod
    def _server_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("адрес сервера пуст")
        return v.strip()


class Subscription(_Model):
    """VLESS-подписка пользователя. HWID генерируется один раз при добавлении
    и хранится: меняющийся идентификатор занимал бы новый слот устройства
    у панели (Remnawave) при каждом запросе и исчерпал бы лимит."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    name: str
    url: str
    enabled: bool = True
    hwid: str = Field(default_factory=lambda: uuid.uuid4().hex)
    last_refresh: str = ""           # ISO-8601, пусто = ещё не обновлялась
    last_count: int = 0              # живых серверов в последнем обновлении
    last_notice: str = ""            # что ответил провайдер, если серверов нет
    # Куда попадают серверы подписки. В «свой» их обычно не пускают:
    # чужой сервер видит весь проходящий через него трафик.
    in_fast: bool = True
    in_own: bool = False


class DomainRule(_Model):
    """Свой домен. Поддомены покрываются автоматически (suffix-правило)."""

    value: str
    policy: Policy = Policy.own

    @field_validator("value")
    @classmethod
    def _looks_like_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if not v or "." not in v or "/" in v or " " in v:
            raise ValueError(f"не похоже на домен: {v!r}")
        return v


class NetworkRule(_Model):
    """Своя подсеть — только для протоколов без имени хоста (Telegram
    MTProto). Общие облачные диапазоны сюда класть нельзя: отсеивать
    попутчиков после этого правила уже некому."""

    value: str
    policy: Policy = Policy.own

    @field_validator("value")
    @classmethod
    def _valid_cidr(cls, v: str) -> str:
        v = v.strip()
        ipaddress.ip_network(v, strict=False)
        return v


class Strategy(str, Enum):
    """Как выбирается сервер внутри группы.

    latency — sing-box сам меряет задержку и берёт лучший (urltest);
    pinned  — всегда один и тот же сервер (selector с фиксированным выбором).
    Других режимов у sing-box нет: раскладки «по очереди» и «по нагрузке»
    он не умеет, и обещать их в интерфейсе нельзя.
    """

    latency = "latency"
    pinned = "pinned"


class Balancer(_Model):
    """Настройки одной группы серверов («свой» или «быстрый»)."""

    strategy: Strategy = Strategy.latency
    interval: str = "5m"        # как часто перемеряется задержка
    tolerance: int = 60         # мс: насколько новый должен выигрывать, чтобы переключиться
    idle_timeout: str = "30m"
    pinned_tag: str = ""        # для strategy=pinned: тег выбранного сервера

    @field_validator("interval", "idle_timeout")
    @classmethod
    def _duration(cls, v: str) -> str:
        if not re.fullmatch(r"\d+(ms|s|m|h)", v.strip()):
            raise ValueError(f"нужен интервал вида 30s, 5m, 1h — получено {v!r}")
        return v.strip()

    @field_validator("tolerance")
    @classmethod
    def _tolerance_sane(cls, v: int) -> int:
        if not 0 <= v <= 10000:
            raise ValueError("допуск задержки задаётся в миллисекундах (0…10000)")
        return v


class Balancing(_Model):
    own: Balancer = Field(default_factory=Balancer)
    fast: Balancer = Field(default_factory=Balancer)


class Stats(_Model):
    """Сбор статистики. Данные не покидают коробку."""

    enabled: bool = True
    keep_days: int = 14
    # Запись «кто на какой сайт ходил». Полезно для разбора («почему
    # медленно», «что жрёт трафик»), но это история посещений — включать
    # осознанно.
    track_hosts: bool = True

    @field_validator("keep_days")
    @classmethod
    def _keep_sane(cls, v: int) -> int:
        if not 1 <= v <= 365:
            raise ValueError("срок хранения — от 1 до 365 дней")
        return v


class Policies(_Model):
    rulesets: dict[str, Policy] = Field(default_factory=dict)  # "vernette:youtube" -> policy
    domains: list[DomainRule] = Field(default_factory=list)
    networks: list[NetworkRule] = Field(default_factory=list)

    @field_validator("rulesets")
    @classmethod
    def _key_has_source(cls, v: dict[str, Policy]) -> dict[str, Policy]:
        for key in v:
            if not re.fullmatch(r"[a-z0-9-]+:[a-z0-9-]+", key):
                raise ValueError(f"ключ набора должен иметь вид «источник:набор»: {key!r}")
        return v


class WgPeer(_Model):
    """Устройство-клиент WireGuard. Приватный ключ хранится, чтобы QR можно
    было показать повторно; режим «не хранить» — задача фазы 4."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    name: str
    private_key: str = ""
    public_key: str
    address: str                     # адрес пира внутри WG-подсети, без маски
    created: str = ""                # ISO-8601


class Wireguard(_Model):
    listen_port: int = 51820
    subnet: str = "10.99.0.0/24"     # .1 — адрес коробки
    private_key: str = ""            # ключ сервера; генерируется при инициализации
    public_key: str = ""
    peers: list[WgPeer] = Field(default_factory=list)

    @property
    def server_address(self) -> str:
        net = ipaddress.ip_network(self.subnet)
        return str(net.network_address + 1)

    def free_address(self) -> str:
        """Первый свободный адрес подсети для нового пира."""
        net = ipaddress.ip_network(self.subnet)
        taken = {p.address for p in self.peers} | {self.server_address}
        for host in net.hosts():
            if str(host) not in taken:
                return str(host)
        raise ValueError("в WG-подсети не осталось свободных адресов")


class AdGuard(_Model):
    """Учётка веб-интерфейса AdGuard.

    Пароль обязателен: интерфейс управляет DNS всей сети, и оставлять его
    без входа, открыв порт, нельзя. Хэш bcrypt — другого формата AdGuard
    не принимает.
    """

    username: str = "admin"
    password_bcrypt: str = ""     # пусто = учётка ещё не создана
    password_plain: str = ""      # показывается владельцу в панели
    port: int = 3000              # http: только редирект на https
    port_https: int = 3443        # рабочий адрес интерфейса


class Dns(_Model):
    adblock: bool = True
    upstreams: list[str] = Field(default_factory=lambda: [
        "https://dns.cloudflare.com/dns-query",
        "https://dns.google/dns-query",
    ])


class Config(_Model):
    """Корень config.yaml."""

    schema_version: int = SCHEMA_VERSION
    mode: Mode = Mode.vps
    endpoint_host: str = ""          # внешний адрес коробки для клиентских WG-конфигов
    admin: Admin = Field(default_factory=Admin)
    own_servers: list[OwnServer] = Field(default_factory=list)
    subscriptions: list[Subscription] = Field(default_factory=list)
    manual_nodes: list[str] = Field(default_factory=list)   # vless://... и т.п.
    policies: Policies = Field(default_factory=Policies)
    balancing: Balancing = Field(default_factory=Balancing)
    wireguard: Wireguard = Field(default_factory=Wireguard)
    dns: Dns = Field(default_factory=Dns)
    stats: Stats = Field(default_factory=Stats)
    adguard: AdGuard = Field(default_factory=AdGuard)
    timezone: str = "Europe/Moscow"   # для подписей на графиках
    work_mode: WorkMode = WorkMode.lan_only

    @model_validator(mode="after")
    def _peer_addresses_inside_subnet(self) -> "Config":
        net = ipaddress.ip_network(self.wireguard.subnet)
        for peer in self.wireguard.peers:
            if ipaddress.ip_address(peer.address) not in net:
                raise ValueError(
                    f"адрес пира {peer.name} ({peer.address}) вне подсети {net}")
        return self

    @property
    def needs_external(self) -> bool:
        """Нужен ли внешний адрес. В режиме «только локальная сеть» его
        может не быть вовсе, и это не ошибка."""
        return self.work_mode is WorkMode.full or self.mode is Mode.vps

    def enabled_own(self) -> list[OwnServer]:
        return [s for s in self.own_servers if s.enabled]

    def enabled_subscriptions(self) -> list[Subscription]:
        return [s for s in self.subscriptions if s.enabled]

    def peer_by_address(self, address: str) -> WgPeer | None:
        return next((p for p in self.wireguard.peers if p.address == address), None)
