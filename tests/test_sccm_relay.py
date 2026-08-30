import json
from types import SimpleNamespace
from ad_enum.core.planner import find_executable
from ad_enum.sccm import discover
from ad_enum.inventory import DomainInventory


def test_sccm_inventory_keeps_candidates_and_unknown_pxe():
    inv = DomainInventory()
    inv.add("computers", "S-1", {"name": "MECM", "dNSHostName": "MECM.sccm.lab"}, "native-ldap")
    result = discover(inv)
    assert result["hosts"][0]["role"] == "site-server-candidate"
    assert result["pxe"]["status"] == "UNKNOWN"
    assert result["management_points"] == []


def test_relayking_is_detectable_from_checkout(monkeypatch, tmp_path):
    monkeypatch.setattr("ad_enum.core.planner.shutil.which", lambda name: None)
    monkeypatch.setattr("ad_enum.core.planner.Path.home", lambda: tmp_path)
    (tmp_path / "RelayKing-Depth").mkdir()
    (tmp_path / "RelayKing-Depth" / "relayking.py").write_text("# fixture")
    assert find_executable("relayking.py").endswith("RelayKing-Depth/relayking.py")


def test_sccm_sql_role_is_spn_evidence():
    inv = DomainInventory()
    inv.add("computers", "S-2", {"name": "MSSQL", "servicePrincipalName": ["MSSQLSvc/sql.sccm.lab:1433"]}, "native-ldap")
    result = discover(inv)
    assert result["sql_servers"][0]["name"] == "MSSQL"
