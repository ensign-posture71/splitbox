"""Модель и хранилище: валидация, round-trip, миграции."""
import pytest
from pydantic import ValidationError

from splitbox import store
from splitbox.model import (SCHEMA_VERSION, Config, DomainRule, NetworkRule,
                            WgPeer)


def test_defaults():
    cfg = Config()
    assert cfg.mode.value == "vps"
    assert cfg.wireguard.server_address == "10.99.0.1"
    assert cfg.dns.adblock is True
    assert cfg.admin.password_hash == ""      # онбординг не пройден


def test_domain_validation():
    DomainRule(value="Rezka.AG").value == "rezka.ag"
    with pytest.raises(ValidationError):
        DomainRule(value="not a domain")
    with pytest.raises(ValidationError):
        DomainRule(value="http://x.com/path")


def test_network_validation():
    NetworkRule(value="91.108.4.0/22")
    with pytest.raises(ValidationError):
        NetworkRule(value="91.108.4.0/99")


def test_ruleset_key_validation():
    with pytest.raises(ValidationError):
        Config.model_validate({"policies": {"rulesets": {"без-источника": "own"}}})


def test_peer_outside_subnet_rejected():
    with pytest.raises(ValidationError, match="вне подсети"):
        Config(wireguard={"peers": [
            WgPeer(name="x", public_key="k", address="192.168.1.5").model_dump()
        ]})


def test_free_address_skips_taken():
    cfg = Config()
    cfg.wireguard.peers.append(WgPeer(name="a", public_key="k", address="10.99.0.2"))
    assert cfg.wireguard.free_address() == "10.99.0.3"


def test_store_roundtrip(tmp_path, sample_config):
    path = tmp_path / "config.yaml"
    store.save(sample_config, path)
    loaded = store.load(path)
    assert loaded == sample_config
    assert oct(path.stat().st_mode)[-3:] == "600"    # в файле ключи WG


def test_store_missing_file_gives_defaults(tmp_path):
    cfg = store.load(tmp_path / "nope.yaml")
    # Прямое сравнение с Config() невозможно: session_secret случайный.
    assert cfg.admin.password_hash == ""
    assert cfg.mode.value == "vps"
    assert cfg.own_servers == []


def test_migrate_rejects_newer_schema():
    with pytest.raises(ValueError, match="более новой версией"):
        store.migrate({"schema_version": SCHEMA_VERSION + 1})


def test_tls_cert_generated_once(tmp_path):
    from splitbox import tls
    cert, key = tls.ensure_cert(tmp_path / "tls", ["10.0.0.1", "box.local"])
    assert cert.exists() and oct(key.stat().st_mode)[-3:] == "600"
    again, _ = tls.ensure_cert(tmp_path / "tls", [])
    assert again.read_bytes() == cert.read_bytes()   # не перевыпускается


def test_adguard_config_has_password_and_public_bind():
    from splitbox import adguard
    from splitbox.model import Config
    cfg = Config()
    cfg.adguard.password_bcrypt = adguard.make_password("secret")
    data = adguard.default_config(cfg)
    assert data["http"]["address"] == "0.0.0.0:3000"
    assert data["users"][0]["name"] == "admin"


def test_adguard_access_migrated_for_existing_install(tmp_path):
    """Старая установка: конфиг на localhost и без пароля — должен
    подтянуться к новым настройкам, не потеряв остального."""
    import yaml
    from splitbox import adguard
    from splitbox.model import Config
    conf = tmp_path / "conf"
    conf.mkdir()
    (conf / "AdGuardHome.yaml").write_text(yaml.safe_dump({
        "http": {"address": "127.0.0.1:3000"}, "users": [],
        "filters": [{"name": "мой список"}]}))
    cfg = Config()
    cfg.adguard.password_bcrypt = adguard.make_password("secret")
    assert adguard.ensure_access(cfg, conf) is True
    data = yaml.safe_load((conf / "AdGuardHome.yaml").read_text())
    assert data["http"]["address"] == "0.0.0.0:3000"
    assert data["users"][0]["name"] == "admin"
    assert data["filters"][0]["name"] == "мой список"   # чужое не тронуто
    assert adguard.ensure_access(cfg, conf) is False    # повторно не меняет
