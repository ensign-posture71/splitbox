import json

from splitbox import traffic
from splitbox.model import Config, TorrentPolicy, WgPeer


class _FakeResp:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def readline(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_row_classifies_torrent_and_udp():
    torrent = traffic.row({
        "id": "t", "upload": 10, "download": 20,
        "metadata": {"sourceIP": "10.99.0.2", "sourcePort": 50123,
                     "destinationIP": "1.2.3.4", "destinationPort": 51413,
                     "network": "udp"},
    })
    suspicious = traffic.row({
        "id": "u", "metadata": {"sourceIP": "10.99.0.2", "sourcePort": 50124,
                                "destinationIP": "5.6.7.8", "destinationPort": 9999,
                                "network": "udp"},
    })
    unknown = traffic.row({"id": "x", "metadata": {}})
    assert torrent["category"] == "torrent" and torrent["confidence"] == "high"
    assert suspicious["category"] == "udp" and suspicious["confidence"] == "suspicious"
    assert unknown["category"] == "unknown"


def test_policy_for_external_peer(monkeypatch):
    cfg = Config()
    cfg.wireguard.peers.append(WgPeer(name="device", public_key="k",
                                      address="10.99.0.2",
                                      torrent_policy=TorrentPolicy.direct))
    assert traffic.policy_for("10.99.0.2", cfg) == "direct"
    assert traffic.policy_for("192.168.88.48", cfg) is None


def test_collect_failure_fails_open(monkeypatch):
    monkeypatch.setattr(traffic.urllib.request, "urlopen",
                        lambda *a, **kw: (_ for _ in ()).throw(OSError()))
    data = traffic.collect()
    assert data == {"alive": False, "connections": [],
                    "up_total": 0, "down_total": 0}
