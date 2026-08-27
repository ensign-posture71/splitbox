"""WireGuard: ключи, пиры, клиентские конфиги.

Ключи — X25519 (cryptography), формат — base64, как у `wg genkey`.
QR-код рисует веб-слой (segno) из текста, который возвращает client_conf().
"""
from __future__ import annotations

import base64
import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .model import Config, WgPeer


def genkey() -> tuple[str, str]:
    """(private_b64, public_b64)."""
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return (base64.b64encode(priv_raw).decode(),
            base64.b64encode(pub_raw).decode())


def pubkey(private_b64: str) -> str:
    raw = base64.b64decode(private_b64)
    priv = X25519PrivateKey.from_private_bytes(raw)
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(pub_raw).decode()


def ensure_server_keys(cfg: Config) -> None:
    """Ключи сервера генерируются один раз при инициализации коробки."""
    if not cfg.wireguard.private_key:
        cfg.wireguard.private_key, cfg.wireguard.public_key = genkey()
    elif not cfg.wireguard.public_key:
        cfg.wireguard.public_key = pubkey(cfg.wireguard.private_key)


def new_peer(cfg: Config, name: str) -> WgPeer:
    """Создать пира со следующим свободным адресом. Модель не сохраняет —
    это делает вызывающий через store.save()."""
    priv, pub = genkey()
    peer = WgPeer(
        name=name,
        private_key=priv,
        public_key=pub,
        address=cfg.wireguard.free_address(),
        created=datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    cfg.wireguard.peers.append(peer)
    return peer


def client_conf(cfg: Config, peer: WgPeer) -> str:
    """Текст .conf для приложения WireGuard (и для QR).

    AllowedIPs включает ::/0 обязательно: на сервере IPv6 дропается
    (политика ipv4_only донора), но если не забрать v6-маршрут у клиента,
    трафик утечёт мимо туннеля по IPv6 на сетях, где он есть.
    DNS — адрес коробки внутри WG-подсети: запросы попадают в AdGuard,
    наружу DNS не ходит.
    """
    if not cfg.endpoint_host:
        raise ValueError("endpoint_host не задан — неизвестен адрес коробки "
                         "для клиентского конфига")
    if not peer.private_key:
        raise ValueError(f"у пира {peer.name} не сохранён приватный ключ — "
                         "конфиг можно было получить только при создании")
    server_ip = cfg.wireguard.server_address
    return "\n".join([
        "[Interface]",
        f"PrivateKey = {peer.private_key}",
        f"Address = {peer.address}/32",
        f"DNS = {server_ip}",
        "",
        "[Peer]",
        f"PublicKey = {cfg.wireguard.public_key}",
        f"Endpoint = {cfg.endpoint_host}:{cfg.wireguard.listen_port}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        "PersistentKeepalive = 25",
        "",
    ])
