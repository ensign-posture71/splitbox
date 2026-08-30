"""Разбор подписок: все четыре формата и фильтры."""
import base64
import json

import pytest

from splitbox import subs

VLESS = ("vless://11111111-2222-3333-4444-555555555555@nl.example.net:443"
         "?security=reality&pbk=PUBKEY&sid=ab12&fp=chrome&sni=cdn.example.org"
         "&type=tcp#%F0%9F%87%B3%F0%9F%87%B1%20NL-1")
TROJAN = "trojan://secretpw@de.example.net:443?sni=de.example.net#DE-1"
SS = "ss://" + base64.urlsafe_b64encode(b"aes-256-gcm:pw").decode().rstrip("=") + \
     "@fi.example.net:8388#FI-1"


def test_raw_links():
    got = subs.parse_payload("\n".join([VLESS, TROJAN, SS, "garbage", "unknown://x"]))
    assert [o["type"] for o in got] == ["vless", "trojan", "shadowsocks"]
    vless = got[0]
    assert vless["server"] == "nl.example.net"
    assert vless["tls"]["reality"]["public_key"] == "PUBKEY"
    assert vless["tls"]["reality"]["short_id"] == "ab12"
    assert vless["tls"]["utls"]["fingerprint"] == "chrome"
    # эмодзи-имя выродилось — тег построен от запасного варианта
    assert vless["tag"].startswith("bk-")


def test_base64_wrapped_links():
    payload = base64.b64encode("\n".join([VLESS, TROJAN]).encode()).decode()
    got = subs.parse_payload(payload)
    assert len(got) == 2


def test_singbox_json():
    payload = json.dumps({"outbounds": [
        {"type": "vless", "tag": "NL", "server": "nl.example.net",
         "server_port": 443, "uuid": "u", "domain_resolver": "remote"},
        {"type": "direct", "tag": "direct"},
        {"type": "vless", "tag": "LTE обход", "server": "1.2.3.4",
         "server_port": 443, "uuid": "u"},
    ]})
    got = subs.parse_payload(payload)
    assert len(got) == 1
    assert got[0]["server"] == "nl.example.net"
    assert "domain_resolver" not in got[0]     # свой резолвер задаётся у нас


def test_xray_json():
    payload = json.dumps([{
        "remarks": "NL-1",
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": "nl.example.net", "port": 443,
                                    "users": [{"id": "uuid-1", "flow": ""}]}]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {"serverName": "cdn.example.org",
                                    "publicKey": "PK", "shortId": "s1",
                                    "fingerprint": "chrome"}},
        }],
    }, {
        "remarks": "Россия → NL",       # цепочка со входом в РФ — отсеивается
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": "ru.example.net", "port": 443,
                                    "users": [{"id": "u2"}]}]},
            "streamSettings": {"network": "tcp"},
        }],
    }])
    got = subs.parse_payload(payload)
    assert len(got) == 1
    assert got[0]["tls"]["reality"]["public_key"] == "PK"


def test_clash_yaml():
    payload = """
port: 7890
proxies:
  - {name: NL-1, type: vless, server: nl.example.net, port: 443, uuid: u1, servername: cdn.example.org, public-key: PK}
  - {name: DE-1, type: trojan, server: de.example.net, port: 443, password: pw, sni: de.example.net}
  - {name: FI-1, type: ss, server: fi.example.net, port: 8388, cipher: aes-256-gcm, password: pw}
rules:
  - MATCH,DIRECT
"""
    got = subs.parse_payload(payload)
    assert [o["type"] for o in got] == ["vless", "trojan", "shadowsocks"]
    assert got[0]["tls"]["reality"]["public_key"] == "PK"


def test_usable_filters():
    dead = {"type": "vless", "tag": "t", "server": "0.0.0.0", "server_port": 1,
            "uuid": "u"}
    bare_ip = {"type": "vless", "tag": "t", "server": "77.88.99.1",
               "server_port": 443, "uuid": "u"}
    ok = {"type": "vless", "tag": "t", "server": "nl.example.net",
          "server_port": 443, "uuid": "u"}
    assert not subs.usable(dead)
    assert not subs.usable(bare_ip)    # голый IP = вероятный узел внутри РФ
    assert subs.usable(ok)


def test_reality_without_pbk_dropped():
    url = "vless://u@host.example.net:443?security=reality#X"
    assert subs.parse_payload(url) == []


def test_safe_tag_uniqueness():
    used: set = set()
    t1 = subs.safe_tag("NL", used)
    t2 = subs.safe_tag("NL", used)
    assert t1 == "bk-nl" and t2 == "bk-nl-2"


def test_parse_manual_link_ok():
    ob = subs.parse_manual_link(VLESS)
    assert ob["server"] == "nl.example.net"


@pytest.mark.parametrize("link,err", [
    ("http://example.com", "неизвестная схема"),
    ("vless://u@0.0.0.0:1?security=tls#stub", "нерабочим"),
    ("mailto:x", "неизвестная схема"),
])
def test_parse_manual_link_errors(link, err):
    with pytest.raises(ValueError, match=err):
        subs.parse_manual_link(link)


def test_strip_meta_removes_internal_fields():
    """Служебные поля не должны попасть в конфиг: sing-box не примет
    незнакомые ключи."""
    ob = subs.parse_payload(VLESS)[0]
    assert "_name" in ob                      # при разборе имя сохраняется
    assert "_name" not in subs.strip_meta(ob)


def test_manual_link_has_no_internal_fields():
    assert not any(k.startswith("_") for k in subs.parse_manual_link(VLESS))


def test_notices_carry_provider_message(monkeypatch):
    """Панель пишет причину отказа в имени заглушки — её надо донести
    до пользователя, а не выбросить вместе с записью."""
    stub = """
proxies:
  - {name: Вы превысили лимит устройств, type: vless, server: 0.0.0.0, port: 1, uuid: x}
"""
    monkeypatch.setattr(subs, "_fetch", lambda *a, **kw: stub)
    r = subs.fetch_subscription("https://example/sub", hwid="h")
    assert r.outbounds == []
    assert "Вы превысили лимит устройств" in r.notices


def test_notices_empty_when_all_alive(monkeypatch):
    monkeypatch.setattr(subs, "_fetch", lambda *a, **kw: VLESS)
    r = subs.fetch_subscription("https://example/sub")
    assert len(r.outbounds) == 1 and r.notices == []
    assert not any(k.startswith("_") for k in r.outbounds[0])
