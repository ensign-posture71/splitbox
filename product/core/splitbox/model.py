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

from pydantic import BaseModel, Field, field_validator, model_validator

SCHEMA_VERSION = 1


class Mode(str, Enum):
    """Режим коробки. vps — вход только через WireGuard; lan_gateway —
    дополнительно tproxy-перехват всего LAN (коробка = default gateway)."""

    vps = "vps"
    lan_gateway = "lan-gateway"


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


class Admin(BaseModel):
    """Доступ к вебке. Пароль хранится как scrypt-хэш (splitbox.auth)."""

    password_hash: str = ""          # пусто = онбординг ещё не пройден
    session_secret: str = Field(default_factory=lambda: secrets.token_hex(32))


class OwnServer(BaseModel):
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

    @field_validator("server")
    @classmethod
    def _server_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("адрес сервера пуст")
        return v.strip()


class Subscription(BaseModel):
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


class DomainRule(BaseModel):
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


class NetworkRule(BaseModel):
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


class Policies(BaseModel):
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


class WgPeer(BaseModel):
    """Устройство-клиент WireGuard. Приватный ключ хранится, чтобы QR можно
    было показать повторно; режим «не хранить» — задача фазы 4."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    name: str
    private_key: str = ""
    public_key: str
    address: str                     # адрес пира внутри WG-подсети, без маски
    created: str = ""                # ISO-8601


class Wireguard(BaseModel):
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


class Dns(BaseModel):
    adblock: bool = True
    upstreams: list[str] = Field(default_factory=lambda: [
        "https://dns.cloudflare.com/dns-query",
        "https://dns.google/dns-query",
    ])


class Config(BaseModel):
    """Корень config.yaml."""

    schema_version: int = SCHEMA_VERSION
    mode: Mode = Mode.vps
    endpoint_host: str = ""          # внешний адрес коробки для клиентских WG-конфигов
    admin: Admin = Field(default_factory=Admin)
    own_servers: list[OwnServer] = Field(default_factory=list)
    subscriptions: list[Subscription] = Field(default_factory=list)
    manual_nodes: list[str] = Field(default_factory=list)   # vless://... и т.п.
    policies: Policies = Field(default_factory=Policies)
    wireguard: Wireguard = Field(default_factory=Wireguard)
    dns: Dns = Field(default_factory=Dns)

    @model_validator(mode="after")
    def _peer_addresses_inside_subnet(self) -> "Config":
        net = ipaddress.ip_network(self.wireguard.subnet)
        for peer in self.wireguard.peers:
            if ipaddress.ip_address(peer.address) not in net:
                raise ValueError(
                    f"адрес пира {peer.name} ({peer.address}) вне подсети {net}")
        return self

    def enabled_own(self) -> list[OwnServer]:
        return [s for s in self.own_servers if s.enabled]

    def enabled_subscriptions(self) -> list[Subscription]:
        return [s for s in self.subscriptions if s.enabled]
