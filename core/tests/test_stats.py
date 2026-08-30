"""Сбор статистики: разбор соединений, агрегация, запросы дашборда."""
import time

import pytest

from splitbox import charts, stats


@pytest.fixture
def db(tmp_path):
    conn = stats.connect(tmp_path / "s.db")
    yield conn
    conn.close()


@pytest.fixture
def collector(tmp_path):
    from splitbox.model import Stats
    return stats.Collector(tmp_path / "s.db", lambda ip: {"10.99.0.2": "Айфон"}.get(ip, ip),
                           lambda: Stats())


def _conn(cid, up, down, src="10.99.0.2", host="example.com", chain="own-vps"):
    return {"id": cid, "upload": up, "download": down, "chains": [chain],
            "metadata": {"sourceIP": src, "host": host}}


def test_direction_classification():
    assert stats.direction("direct") == "direct"
    assert stats.direction("own-vps") == "own"
    assert stats.direction("bk-nl") == "fast"
    assert stats.direction("fast-out") == "fast"


def test_deltas_not_absolute(collector, monkeypatch):
    """Счётчики соединения накопительные — писать надо прирост, иначе
    трафик утроится на третьем опросе."""
    payload = {"connections": [_conn("a", 100, 200)]}
    monkeypatch.setattr(stats.urllib.request, "urlopen",
                        lambda *a, **kw: _FakeResp(payload))
    first = collector.poll_once()
    assert (first[0].up, first[0].down) == (100, 200)

    payload["connections"] = [_conn("a", 150, 260)]
    second = collector.poll_once()
    assert (second[0].up, second[0].down) == (50, 60)   # только прирост


def test_peer_name_resolved(collector, monkeypatch):
    monkeypatch.setattr(stats.urllib.request, "urlopen",
                        lambda *a, **kw: _FakeResp({"connections": [_conn("a", 1, 1)]}))
    assert collector.poll_once()[0].peer == "Айфон"


def test_restart_resets_counters(collector, monkeypatch):
    """sing-box перезапускается при каждом применении настроек — после
    обрыва счётчики начинаются с нуля, и это не должно давать выброс."""
    monkeypatch.setattr(stats.urllib.request, "urlopen",
                        lambda *a, **kw: _FakeResp({"connections": [_conn("a", 500, 500)]}))
    collector.poll_once()
    monkeypatch.setattr(stats.urllib.request, "urlopen",
                        lambda *a, **kw: (_ for _ in ()).throw(OSError()))
    assert collector.poll_once() == []
    assert collector.seen == {}


def test_store_and_queries(db, collector):
    now = time.time()
    samples = [
        stats.Sample("Айфон", "own-vps", "openai.com", 10, 100),
        stats.Sample("Айфон", "bk-nl", "youtube.com", 5, 500),
        stats.Sample("Ноут", "direct", "ya.ru", 1, 50),
    ]
    collector.store(db, samples, now, track_hosts=True)

    assert stats.totals(db, 24)["total"] == 666
    peers = stats.by_peer(db, 24)
    assert peers[0]["peer"] == "Айфон" and peers[0]["total"] == 615
    dirs = {d["direction"]: d["total"] for d in stats.by_direction(db, 24)}
    assert dirs == {"own": 110, "fast": 505, "direct": 51}
    hosts = stats.top_hosts(db, 24)
    assert hosts[0]["host"] == "youtube.com"
    assert stats.top_hosts(db, 24, peer="Ноут")[0]["host"] == "ya.ru"


def test_hosts_not_recorded_when_disabled(db, collector):
    collector.store(db, [stats.Sample("Айфон", "own-vps", "secret.example", 1, 1)],
                    time.time(), track_hosts=False)
    assert stats.top_hosts(db, 24) == []
    assert stats.totals(db, 24)["total"] == 2      # трафик всё равно посчитан


def test_cleanup_removes_old(db, collector):
    old = time.time() - 40 * 86400
    collector.store(db, [stats.Sample("X", "direct", "old.example", 5, 5)], old, True)
    collector.cleanup(db, time.time(), keep_days=14)
    assert stats.totals(db, 24 * 90)["total"] == 0


def test_charts_render_without_data():
    assert "Данных пока нет" in charts.area_chart([], 24)
    assert "нет данных" in charts.donut([])


def test_charts_render_svg(db, collector):
    now = time.time()
    collector.store(db, [stats.Sample("A", "own-vps", "a.example", 10, 20)], now, True)
    collector.store(db, [stats.Sample("A", "bk-nl", "b.example", 5, 30)], now - 120, True)
    svg = charts.area_chart(stats.series(db, 24), 24, "Europe/Moscow")
    assert svg.startswith("<svg") and "polyline" in svg
    assert charts.donut(stats.by_direction(db, 24)).startswith("<svg")


def test_human_bytes():
    assert stats.human_bytes(512) == "512 Б"
    assert stats.human_bytes(2048) == "2 КБ"
    assert stats.human_bytes(5 * 1024**3) == "5.0 ГБ"


class _FakeResp:
    """clash_api отдаёт поток JSON-строк; читаем первую."""

    def __init__(self, payload):
        import json
        self._data = json.dumps(payload).encode()

    def readline(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_localhost_named_as_box(tmp_path, monkeypatch):
    """Проба здоровья ходит с localhost — в списке устройств она не должна
    выглядеть как ещё один клиент."""
    monkeypatch.setenv("SPLITBOX_STATE", str(tmp_path))
    import importlib
    from splitbox import paths
    importlib.reload(paths)
    from splitbox.api import state, app as app_mod
    importlib.reload(state)
    importlib.reload(app_mod)
    assert app_mod._resolve_peer("127.0.0.1") == "коробка (проверка связи)"
    assert app_mod._resolve_peer("") == "неизвестно"
