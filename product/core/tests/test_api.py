"""Интеграционные тесты веб-приложения: онбординг, авторизация, страницы.

Сеть и перезапуск sing-box подменяются: тесты гоняют логику и состояние,
а не туннель. Боевой путь apply проверяется на стенде (см. план, фаза 1).
"""
import importlib

import pytest

VLESS = ("vless://11111111-2222-3333-4444-555555555555@nl.example.net:443"
         "?security=reality&pbk=PUBKEY&sid=ab12&fp=chrome&sni=cdn.example.org"
         "&type=tcp#NL-1")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SPLITBOX_STATE", str(tmp_path))
    # paths вычисляются при импорте — перечитываем модули под новый STATE
    from splitbox import paths
    importlib.reload(paths)
    from splitbox import apply as apply_mod
    importlib.reload(apply_mod)
    from splitbox.api import state, app as app_mod
    importlib.reload(state)
    importlib.reload(app_mod)

    monkeypatch.setattr(app_mod.apply_mod, "apply",
                        lambda cfg: "Применено (тест)")
    from fastapi.testclient import TestClient
    return TestClient(app_mod.app)


def _onboard(client, password="secret123"):
    client.post("/setup/password",
                data={"password": password, "password2": password})


def test_root_redirects_to_setup(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/setup"


def test_password_too_short(client):
    r = client.post("/setup/password",
                    data={"password": "short", "password2": "short"},
                    follow_redirects=False)
    assert "step=1" in r.headers["location"]


def test_onboarding_with_own_server(client):
    _onboard(client)
    r = client.post("/setup/source", data={"link": VLESS},
                    follow_redirects=False)
    assert "step=3" in r.headers["location"], r.headers["location"]

    r = client.post("/setup/device", data={"name": "Айфон"},
                    follow_redirects=False)
    assert "step=4" in r.headers["location"]

    from splitbox.api import state
    cfg = state.get()
    assert cfg.own_servers[0].server == "nl.example.net"
    assert cfg.own_servers[0].reality_public_key == "PUBKEY"
    # пресет политик включился сам
    assert cfg.policies.rulesets
    assert cfg.wireguard.peers[0].name == "Айфон"
    assert cfg.wireguard.private_key

    # QR и conf отдаются
    peer = cfg.wireguard.peers[0]
    assert client.get(f"/devices/{peer.id}/qr.svg").status_code == 200
    conf = client.get(f"/devices/{peer.id}/conf").text
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in conf


def test_bad_link_shows_error(client):
    _onboard(client)
    r = client.post("/setup/source", data={"link": "ftp://junk"},
                    follow_redirects=False)
    assert "step=2" in r.headers["location"]
    assert "err=" in r.headers["location"]


def test_login_flow(client):
    _onboard(client)
    client.cookies.clear()
    r = client.get("/services", follow_redirects=False)
    assert r.headers["location"] == "/login"
    r = client.post("/login", data={"password": "wrong"},
                    follow_redirects=False)
    assert "err=" in r.headers["location"]
    r = client.post("/login", data={"password": "secret123"},
                    follow_redirects=False)
    assert r.headers["location"] == "/"
    assert client.get("/services").status_code == 200


def test_services_save(client):
    _onboard(client)
    r = client.post("/services", data={"p:vernette:youtube": "fast",
                                       "p:vernette:openai": "own",
                                       "p:vernette:rkn": "off"},
                    follow_redirects=False)
    from splitbox.api import state
    policies = state.get().policies.rulesets
    assert policies["vernette:youtube"].value == "fast"
    assert policies["vernette:openai"].value == "own"
    assert "vernette:rkn" not in policies      # off не хранится


def test_lists_save_and_validation(client):
    _onboard(client)
    client.post("/lists", data={"row": ["d|fast|rezka.ag",
                                        "n|own|91.108.4.0/22",
                                        "d|own|"]})       # пустая строка — мимо
    from splitbox.api import state
    cfg = state.get()
    assert cfg.policies.domains[0].value == "rezka.ag"
    assert cfg.policies.networks[0].value == "91.108.4.0/22"

    r = client.post("/lists", data={"row": ["n|own|не-подсеть"]},
                    follow_redirects=False)
    assert "err=" in r.headers["location"]
    # плохая строка не затёрла хорошее состояние
    assert state.get().policies.networks[0].value == "91.108.4.0/22"


def test_device_add_delete(client):
    _onboard(client)
    client.post("/setup/source", data={"link": VLESS})
    client.post("/devices/add", data={"name": "Ноут"})
    from splitbox.api import state
    peers = state.get().wireguard.peers
    assert peers[0].name == "Ноут"
    client.post(f"/devices/{peers[0].id}/delete")
    assert state.get().wireguard.peers == []


def test_backup_download(client):
    _onboard(client)
    r = client.get("/settings/backup")
    assert "password_hash" in r.text


def test_setup_token_gate(client, monkeypatch):
    """На VPS до установки пароля мастер открывается только по ссылке
    с токеном из инсталлера."""
    monkeypatch.setenv("SPLITBOX_SETUP_TOKEN", "sekret")
    assert client.get("/setup").status_code == 403
    r = client.post("/setup/password",
                    data={"password": "12345678", "password2": "12345678"})
    assert r.status_code == 403
    assert client.get("/setup?token=sekret").status_code == 200
    # токен переехал в cookie — POST проходит
    r = client.post("/setup/password",
                    data={"password": "12345678", "password2": "12345678"},
                    follow_redirects=False)
    assert r.status_code == 303
    # после установки пароля токен больше не нужен
    assert client.get("/setup?step=2").status_code == 200


def test_restore_backup_roundtrip(client):
    _onboard(client)
    client.post("/setup/source", data={"link": VLESS})
    backup = client.get("/settings/backup").text

    # ломаем состояние и восстанавливаем
    from splitbox.api import state
    state.update(lambda c: c.own_servers.clear())
    assert state.get().own_servers == []
    r = client.post("/settings/restore",
                    files={"backup": ("config.yaml", backup, "text/yaml")},
                    follow_redirects=False)
    assert "err=" not in r.headers["location"], r.headers["location"]
    assert state.get().own_servers[0].server == "nl.example.net"


def test_restore_rejects_garbage(client):
    _onboard(client)
    from splitbox.api import state
    before = state.get().admin.password_hash
    r = client.post("/settings/restore",
                    files={"backup": ("x.yaml", "just: garbage", "text/yaml")},
                    follow_redirects=False)
    assert "err=" in r.headers["location"]
    assert state.get().admin.password_hash == before   # ничего не затёрто


def test_own_server_delete(client):
    _onboard(client)
    client.post("/setup/source", data={"link": VLESS})
    from splitbox.api import state
    assert len(state.get().own_servers) == 1
    client.post("/servers/own/0/delete")
    assert state.get().own_servers == []


def test_servers_page_and_bulk_save(client):
    _onboard(client)
    client.post("/setup/source", data={"link": VLESS})
    assert client.get("/servers").status_code == 200

    r = client.post("/servers", data={
        "own.0.name": "Главный",
        "own.0.enabled": "1",
        "own.0.in_own": "1",
        # in_fast не отмечен — сервер выходит из группы скорости
        "bal.own.strategy": "latency",
        "bal.own.interval": "2m",
        "bal.own.tolerance": "120",
        "bal.fast.strategy": "pinned",
        "bal.fast.interval": "5m",
        "bal.fast.tolerance": "60",
        "bal.fast.pinned_tag": "bk-nl",
    }, follow_redirects=False)
    assert "err=" not in r.headers["location"], r.headers["location"]

    from splitbox.api import state
    cfg = state.get()
    assert cfg.own_servers[0].name == "Главный"
    assert cfg.own_servers[0].in_own and not cfg.own_servers[0].in_fast
    assert cfg.balancing.own.interval == "2m"
    assert cfg.balancing.own.tolerance == 120
    assert cfg.balancing.fast.strategy.value == "pinned"
    assert cfg.balancing.fast.pinned_tag == "bk-nl"


def test_servers_save_rejects_bad_interval(client):
    _onboard(client)
    client.post("/setup/source", data={"link": VLESS})
    r = client.post("/servers", data={
        "own.0.enabled": "1", "own.0.in_own": "1",
        "bal.own.strategy": "latency", "bal.own.interval": "пять минут",
        "bal.own.tolerance": "60",
        "bal.fast.strategy": "latency", "bal.fast.interval": "5m",
        "bal.fast.tolerance": "60",
    }, follow_redirects=False)
    assert "err=" in r.headers["location"]
    from splitbox.api import state
    assert state.get().balancing.own.interval == "5m"     # прежнее уцелело


def test_multiple_sources_can_coexist(client):
    """Подписок и своих серверов может быть сколько угодно."""
    _onboard(client)
    for i in range(3):
        client.post("/servers/add", data={
            "name": f"Сервер {i}",
            "url": VLESS.replace("nl.example.net", f"s{i}.example.net")})
    for i in range(2):
        client.post("/servers/add", data={"name": f"Подписка {i}",
                                          "url": f"https://sub{i}.example/x"})
    from splitbox.api import state
    cfg = state.get()
    assert len(cfg.own_servers) == 3 and len(cfg.subscriptions) == 2


def test_subscription_hwid_editable(client):
    """После находки с лимитом устройств идентификатор должен быть
    правим руками — иначе подписку не оживить."""
    _onboard(client)
    client.post("/servers/add", data={"url": "https://sub.example/x"})
    from splitbox.api import state
    sub = state.get().subscriptions[0]
    client.post("/servers", data={
        f"sub.{sub.id}.name": "Основная",
        f"sub.{sub.id}.enabled": "1",
        f"sub.{sub.id}.in_fast": "1",
        f"sub.{sub.id}.hwid": "8c5ee7df-a08c-4837-9b72-5026a9fd1e33",
        "bal.own.strategy": "latency", "bal.own.interval": "5m", "bal.own.tolerance": "60",
        "bal.fast.strategy": "latency", "bal.fast.interval": "5m", "bal.fast.tolerance": "60",
    })
    assert state.get().subscriptions[0].hwid == "8c5ee7df-a08c-4837-9b72-5026a9fd1e33"


def test_stats_page_renders(client):
    _onboard(client)
    assert client.get("/stats").status_code == 200
    assert client.get("/stats?hours=168").status_code == 200
