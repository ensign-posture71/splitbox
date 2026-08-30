"""Рендер конфига sing-box: режимы, деградации, инварианты донора."""
import json
from pathlib import Path

import pytest

from splitbox import render
from splitbox.model import Mode

from conftest import KEY_C

GOLDEN = Path(__file__).parent / "golden"


def _outbound_tags(cfg):
    return {o["tag"] for o in cfg["outbounds"]}


def _rules(cfg):
    return cfg["route"]["rules"]


def test_vps_mode_has_no_tproxy(sample_config, backup_outbounds):
    cfg = render.render_config(sample_config, backup_outbounds)
    tags = [i["tag"] for i in cfg["inbounds"]]
    assert "tproxy-in" not in tags
    assert "local-probe" in tags


def test_lan_mode_keeps_tproxy(sample_config, backup_outbounds):
    sample_config.mode = Mode.lan_gateway
    cfg = render.render_config(sample_config, backup_outbounds)
    assert "tproxy-in" in [i["tag"] for i in cfg["inbounds"]]


def test_wireguard_endpoint(sample_config, backup_outbounds):
    cfg = render.render_config(sample_config, backup_outbounds)
    ep = cfg["endpoints"][0]
    assert ep["type"] == "wireguard"
    assert ep["address"] == ["10.99.0.1/24"]
    assert ep["listen_port"] == 51820
    assert ep["peers"] == [{"public_key": KEY_C,
                            "allowed_ips": ["10.99.0.2/32"]}]


def test_hijack_dns_before_private(sample_config, backup_outbounds):
    """DNS WG-клиентов идёт на приватный адрес; правило ip_is_private
    перехватило бы его первым и отправило в никуда."""
    rules = _rules(render.render_config(sample_config, backup_outbounds))
    actions = [r.get("action") or r.get("outbound") for r in rules]
    hijack = next(i for i, r in enumerate(rules) if r.get("action") == "hijack-dns")
    private = next(i for i, r in enumerate(rules) if r.get("ip_is_private"))
    assert hijack < private


def test_local_probe_goes_to_own(sample_config, backup_outbounds):
    """Проба должна идти боевым путём через туннель безусловно — иначе
    health-check зеленеет на мёртвом туннеле (донорская O32)."""
    rules = _rules(render.render_config(sample_config, backup_outbounds))
    probe = next(r for r in rules if r.get("inbound") == ["local-probe"])
    # Кириллица имени срезается, тег построен от хоста (донорская логика тегов)
    assert probe["outbound"] == "own-vps"


def test_single_own_server_tag_substitution(sample_config, backup_outbounds):
    cfg = render.render_config(sample_config, backup_outbounds)
    tags = _outbound_tags(cfg)
    assert "own-out" not in tags                 # алиас не нужен при одном своём
    assert "fast-out" in tags
    fast = next(o for o in cfg["outbounds"] if o["tag"] == "fast-out")
    # свой сервер в группе автовыбора наравне с резервом
    assert fast["outbounds"][0].startswith("own-")
    assert "bk-nl-1" in fast["outbounds"]


def test_no_backups_degrades_fast_to_own(sample_config):
    cfg = render.render_config(sample_config, [])
    tags = _outbound_tags(cfg)
    assert "fast-out" not in tags
    for rule in _rules(cfg):
        assert rule.get("outbound") != "fast-out"


def test_no_own_degrades_own_to_fast(sample_config, backup_outbounds):
    sample_config.own_servers = []
    cfg = render.render_config(sample_config, backup_outbounds)
    for rule in _rules(cfg):
        assert rule.get("outbound") != "own-out"
    fast = next(o for o in cfg["outbounds"] if o["tag"] == "fast-out")
    assert fast["outbounds"] == ["bk-nl-1", "bk-de-1"]


def test_no_servers_at_all_is_error(sample_config):
    sample_config.own_servers = []
    with pytest.raises(render.RenderError, match="нет ни одного сервера"):
        render.render_config(sample_config, [])


def test_two_own_servers_make_urltest(sample_config, backup_outbounds):
    second = sample_config.own_servers[0].model_copy(
        update={"name": "Второй", "server": "vps2.example.com"})
    sample_config.own_servers.append(second)
    cfg = render.render_config(sample_config, backup_outbounds)
    own_out = next(o for o in cfg["outbounds"] if o["tag"] == "own-out")
    assert own_out["type"] == "urltest"
    assert len(own_out["outbounds"]) == 2


def test_empty_rule_arrays_dropped(sample_config, backup_outbounds):
    sample_config.policies.networks = []        # CIDR-правила должны исчезнуть
    cfg = render.render_config(sample_config, backup_outbounds)
    for rule in _rules(cfg):
        assert rule.get("ip_cidr") != []
        assert rule.get("rule_set") != []
        assert rule.get("domain") != []


def test_no_comments_and_no_placeholders(sample_config, backup_outbounds):
    text = render.render_json(sample_config, backup_outbounds)
    assert '"//' not in text
    assert "${" not in text


def test_flow_absent_when_empty(sample_config, backup_outbounds):
    """D10: flow не выставляется, если сервер его не ждёт."""
    cfg = render.render_config(sample_config, backup_outbounds)
    own = next(o for o in cfg["outbounds"] if o["tag"].startswith("own-"))
    assert "flow" not in own


def test_domain_suffix_has_leading_dot(sample_config, backup_outbounds):
    cfg = render.render_config(sample_config, backup_outbounds)
    fast_domains = next(r for r in _rules(cfg)
                        if r.get("domain") and r["outbound"] == "fast-out")
    assert "rezka.ag" in fast_domains["domain"]
    assert ".rezka.ag" in fast_domains["domain_suffix"]


def test_ruleset_tags_prefixed(sample_config, backup_outbounds):
    cfg = render.render_config(sample_config, backup_outbounds)
    tags = {rs["tag"] for rs in cfg["route"]["rule_set"]}
    # Префикс источника обязателен: одноимённые наборы затёрли бы друг друга.
    assert tags == {"vr-youtube", "vr-openai", "mc-notion"}


def test_golden_vps(sample_config, backup_outbounds):
    """Полный конфиг байт-в-байт: любое изменение рендера должно быть видно
    в диффе golden-файла, а не проскакивать незамеченным."""
    got = render.render_json(sample_config, backup_outbounds)
    golden = GOLDEN / "vps.json"
    if not golden.exists():                      # первичная генерация
        golden.parent.mkdir(exist_ok=True)
        golden.write_text(got)
    assert got == golden.read_text()
    json.loads(got)                              # и это валидный JSON


def test_golden_lan(sample_config, backup_outbounds):
    sample_config.mode = Mode.lan_gateway
    got = render.render_json(sample_config, backup_outbounds)
    golden = GOLDEN / "lan.json"
    if not golden.exists():
        golden.parent.mkdir(exist_ok=True)
        golden.write_text(got)
    assert got == golden.read_text()


# --- Балансировка и участие серверов в группах ------------------------------

def test_pinned_strategy_makes_selector(sample_config, backup_outbounds):
    from splitbox.model import Strategy
    sample_config.balancing.fast.strategy = Strategy.pinned
    sample_config.balancing.fast.pinned_tag = "bk-de-1"
    cfg = render.render_config(sample_config, backup_outbounds)
    fast = next(o for o in cfg["outbounds"] if o["tag"] == "fast-out")
    assert fast["type"] == "selector"
    assert fast["default"] == "bk-de-1"


def test_pinned_falls_back_to_first_when_tag_gone(sample_config, backup_outbounds):
    from splitbox.model import Strategy
    sample_config.balancing.fast.strategy = Strategy.pinned
    sample_config.balancing.fast.pinned_tag = "сервер-которого-нет"
    cfg = render.render_config(sample_config, backup_outbounds)
    fast = next(o for o in cfg["outbounds"] if o["tag"] == "fast-out")
    assert fast["default"] in fast["outbounds"]


def test_balancer_params_reach_config(sample_config, backup_outbounds):
    sample_config.balancing.fast.interval = "90s"
    sample_config.balancing.fast.tolerance = 150
    cfg = render.render_config(sample_config, backup_outbounds)
    fast = next(o for o in cfg["outbounds"] if o["tag"] == "fast-out")
    assert fast["interval"] == "90s" and fast["tolerance"] == 150


def test_own_server_excluded_from_fast(sample_config, backup_outbounds):
    """Свой сервер можно не пускать в группу скорости."""
    sample_config.own_servers[0].in_fast = False
    cfg = render.render_config(sample_config, backup_outbounds)
    fast = next(o for o in cfg["outbounds"] if o["tag"] == "fast-out")
    assert not any(t.startswith("own-") for t in fast["outbounds"])


def test_backup_can_join_own_group(sample_config, backup_outbounds):
    """Сервер подписки, помеченный как доверенный, попадает и в «свой»."""
    backup_outbounds[0]["_groups"] = ["fast", "own"]
    cfg = render.render_config(sample_config, backup_outbounds)
    own = next(o for o in cfg["outbounds"] if o["tag"] == "own-out")
    assert "bk-nl-1" in own["outbounds"]
    # служебное поле не должно утечь в конфиг
    assert all("_groups" not in o for o in cfg["outbounds"])


def test_no_group_membership_is_error(sample_config, backup_outbounds):
    sample_config.own_servers[0].in_own = False
    sample_config.own_servers[0].in_fast = False
    for ob in backup_outbounds:
        ob["_groups"] = []
    with pytest.raises(render.RenderError, match="ни в одну группу"):
        render.render_config(sample_config, backup_outbounds)
