"""WireGuard: ключи и клиентские конфиги."""
import base64

import pytest

from splitbox import wg
from splitbox.model import Config


def test_genkey_roundtrip():
    priv, pub = wg.genkey()
    assert len(base64.b64decode(priv)) == 32
    assert wg.pubkey(priv) == pub


def test_ensure_server_keys_idempotent():
    cfg = Config()
    wg.ensure_server_keys(cfg)
    priv = cfg.wireguard.private_key
    assert priv and cfg.wireguard.public_key == wg.pubkey(priv)
    wg.ensure_server_keys(cfg)
    assert cfg.wireguard.private_key == priv     # повторный вызов не перегенерирует


def test_new_peer_and_conf():
    cfg = Config(endpoint_host="box.example.com")
    wg.ensure_server_keys(cfg)
    peer = wg.new_peer(cfg, "iphone")
    assert peer.address == "10.99.0.2"
    conf = wg.client_conf(cfg, peer)
    assert f"PublicKey = {cfg.wireguard.public_key}" in conf
    assert "Endpoint = box.example.com:51820" in conf
    assert "DNS = 10.99.0.1" in conf
    # v6 забирается в туннель обязательно — иначе утечка мимо туннеля
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in conf


def test_conf_requires_endpoint_host():
    cfg = Config()
    wg.ensure_server_keys(cfg)
    peer = wg.new_peer(cfg, "x")
    with pytest.raises(ValueError, match="endpoint_host"):
        wg.client_conf(cfg, peer)
