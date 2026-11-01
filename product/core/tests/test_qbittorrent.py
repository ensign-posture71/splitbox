import json

from splitbox import qbittorrent


def test_fetch_not_configured(monkeypatch):
    monkeypatch.delenv("QBITTORRENT_STATS_URL", raising=False)
    monkeypatch.delenv("QBITTORRENT_STATS_TOKEN", raising=False)
    data = qbittorrent.fetch(24)
    assert data["configured"] is False
    assert data["available"] is False
    assert data["error"] == "агент не настроен"


def test_fetch_agent_data(monkeypatch):
    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return json.dumps({"configured": True, "available": True,
                               "totals": {"up": 10, "down": 20, "total": 30},
                               "counts": {"active": 1}}).encode()
    def fake_urlopen(*args, **kwargs):
        return FakeResp()
    monkeypatch.setenv("QBITTORRENT_STATS_URL", "http://agent.invalid")
    monkeypatch.setenv("QBITTORRENT_STATS_TOKEN", "secret")
    monkeypatch.setattr(qbittorrent.urllib.request, "urlopen", fake_urlopen)
    data = qbittorrent.fetch(24)
    assert data["configured"] is True
    assert data["available"] is True
    assert data["totals"]["total"] == 30
