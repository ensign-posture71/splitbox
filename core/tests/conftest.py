import base64

import pytest

from splitbox import wg
from splitbox.model import (Config, DomainRule, Mode, NetworkRule, OwnServer,
                            Policy, Subscription)

# Детерминированные, но криптографически валидные 32-байтовые ключи:
# sing-box check по-настоящему разбирает public_key/private_key, и мусор
# вместо base64-x25519 роняет проверку golden-конфигов. Кодировки разные:
# Reality ждёт base64url БЕЗ паддинга, WireGuard — обычный base64 с паддингом.
REALITY_PBK = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
KEY_B = base64.b64encode(bytes(range(32, 64))).decode()
KEY_C = base64.b64encode(bytes(range(64, 96))).decode()


@pytest.fixture
def sample_config() -> Config:
    """Конфигурация, похожая на боевую домашнюю: свой Reality-сервер,
    одна подписка, немного наборов и своих списков, один WG-пир."""
    cfg = Config(
        mode=Mode.vps,
        endpoint_host="box.example.com",
        own_servers=[OwnServer(
            name="Мой VPS",
            server="vps.example.com",
            server_port=443,
            uuid="11111111-2222-3333-4444-555555555555",
            sni="cdn.example.org",
            reality_public_key=REALITY_PBK,
            reality_short_id="0123ab",
        )],
        subscriptions=[Subscription(name="Основная", url="https://sub.example/abc",
                                    hwid="deadbeef")],
    )
    cfg.policies.rulesets = {
        "vernette:youtube": Policy.fast,
        "vernette:openai": Policy.own,
        "metacubex:notion": Policy.fast,
    }
    cfg.policies.domains = [
        DomainRule(value="rezka.ag", policy=Policy.fast),
        DomainRule(value="example-own.com", policy=Policy.own),
    ]
    cfg.policies.networks = [
        NetworkRule(value="91.108.4.0/22", policy=Policy.own),
    ]
    # Ключи фиксированные, чтобы golden-файлы были воспроизводимы.
    cfg.wireguard.private_key = KEY_B
    cfg.wireguard.public_key = wg.pubkey(KEY_B)
    peer = wg.WgPeer(id="p1", name="iphone", public_key=KEY_C,
                     private_key=KEY_C, address="10.99.0.2",
                     created="2026-08-27T00:00:00Z")
    cfg.wireguard.peers.append(peer)
    return cfg


@pytest.fixture
def backup_outbounds() -> list[dict]:
    return [
        {"type": "vless", "tag": "bk-nl-1", "server": "nl.example.net",
         "server_port": 443, "uuid": "aaa", "packet_encoding": "xudp"},
        {"type": "trojan", "tag": "bk-de-1", "server": "de.example.net",
         "server_port": 443, "password": "x",
         "tls": {"enabled": True, "server_name": "de.example.net"}},
    ]
