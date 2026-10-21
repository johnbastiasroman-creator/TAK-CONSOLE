# SPDX-License-Identifier: Apache-2.0
from takconsole.core import firewall, settings
from takconsole.core.shell import Result

PORTS = [{"port": "8089", "proto": "tcp"}, {"port": "9993", "proto": "udp", "always": True}]


def test_policy_all(data_dir):
    cmds = firewall.planned_rules(PORTS, "takserver")
    assert cmds[0] == ["ufw", "allow", "proto", "tcp", "to", "any", "port", "8089",
                       "comment", "tak-console:takserver"]
    assert len(cmds) == 2


def test_policy_zerotier(data_dir, monkeypatch):
    settings.update_section("network", {"exposure": "zerotier", "zt_ifaces": ["ztabc123"]})
    monkeypatch.setattr(firewall.system, "interfaces", lambda: [])
    cmds = firewall.planned_rules(PORTS, "takserver")
    assert ["ufw", "allow", "in", "on", "ztabc123", "proto", "tcp", "to", "any", "port", "8089",
            "comment", "tak-console:takserver"] in cmds
    # 9993 siempre abierto en todas las interfaces
    assert any("9993" in c and "on" not in c for c in cmds)


def test_policy_zerotier_lan(data_dir, monkeypatch):
    settings.update_section("network", {"exposure": "zerotier_lan", "lan_cidr": "192.168.1.0/24",
                                        "zt_ifaces": []})
    monkeypatch.setattr(firewall.system, "interfaces",
                        lambda: [{"name": "zt9", "kind": "zerotier", "addresses": ["10.1.1.1"]}])
    cmds = firewall.planned_rules([{"port": "64738", "proto": "udp"}], "mumble")
    assert ["ufw", "allow", "in", "on", "zt9", "proto", "udp", "to", "any", "port", "64738",
            "comment", "tak-console:mumble"] in cmds
    assert ["ufw", "allow", "proto", "udp", "from", "192.168.1.0/24", "to", "any", "port",
            "64738", "comment", "tak-console:mumble"] in cmds


def test_bad_iface_names_ignored(data_dir, monkeypatch):
    settings.update_section("network", {"zt_ifaces": ["zt1; rm -rf /", "eth0", "ztok"]})
    monkeypatch.setattr(firewall.system, "interfaces", lambda: [])
    assert firewall.zerotier_ifaces() == ["ztok"]


def test_remove_rules_deletes_only_tagged_descending(data_dir, monkeypatch):
    status = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # tak-console:core
[ 2] 8089/tcp                   ALLOW IN    Anywhere                   # tak-console:takserver
[ 3] 80/tcp                     ALLOW IN    Anywhere
[ 4] 8089/tcp on zt1            ALLOW IN    Anywhere                   # tak-console:takserver
[ 5] 8089/tcp (v6)              ALLOW IN    Anywhere (v6)              # tak-console:takserver
[ 6] 1234/tcp                   ALLOW IN    Anywhere                   # tak-console:takserverx
"""
    monkeypatch.setattr(firewall, "available", lambda: True)
    monkeypatch.setattr(firewall, "capture", lambda argv, **k: Result(0, status))
    calls = []
    monkeypatch.setattr(firewall, "run", lambda argv, **k: calls.append(argv) or Result(0, ""))
    firewall.remove_rules("takserver")
    assert [c[-1] for c in calls] == ["5", "4", "2"]


def test_validate_cidr():
    assert firewall.validate_cidr("192.168.1.7/24") == "192.168.1.0/24"
    import pytest
    with pytest.raises(ValueError):
        firewall.validate_cidr("no-es-red")
