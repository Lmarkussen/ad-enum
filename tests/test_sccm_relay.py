import json
from types import SimpleNamespace
from ad_enum.core.planner import find_executable
from ad_enum.sccm import discover, normalize_relayking
from ad_enum.inventory import DomainInventory


def test_sccm_inventory_keeps_candidates_and_unknown_pxe():
    inv = DomainInventory()
    inv.add("computers", "S-1", {"name": "MECM", "dNSHostName": "MECM.sccm.lab"}, "native-ldap")
    result = discover(inv)
    assert result["hosts"][0]["role"] == "site-server-candidate"
    assert result["pxe"]["status"] == "UNKNOWN"
    assert result["management_points"] == []


def test_identity_attributes_cover_the_sccm_role_hints():
    from ad_enum.ldap_collect import IDENTITY_ATTRIBUTES

    # sccm.discover() reads these; missing name/cn silently disabled the
    # host-name based SQL / site-server classification.
    assert {"name", "cn"} <= set(IDENTITY_ATTRIBUTES)
    assert {"objectSid", "sAMAccountName", "dNSHostName", "servicePrincipalName",
            "userAccountControl"} <= set(IDENTITY_ATTRIBUTES)


def test_discover_classifies_hosts_by_name_when_no_spn_is_published():
    inv = DomainInventory()
    inv.add("computers", "S-1", {"name": "MSSQL", "dNSHostName": "MSSQL.sccm.lab"}, "native-ldap")
    inv.add("computers", "S-2", {"name": "MECM", "dNSHostName": "MECM.sccm.lab"}, "native-ldap")

    result = discover(inv)

    assert [host["name"] for host in result["hosts"]] == ["MSSQL", "MECM"]
    assert result["sql_servers"][0]["name"] == "MSSQL"
    assert result["hosts"][1]["role"] == "site-server-candidate"


def test_discover_handles_list_valued_ldap_attributes():
    inv = DomainInventory()
    inv.add("computers", "S-1", {"name": ["MSSQL"], "dNSHostName": ["MSSQL.sccm.lab"],
                                 "sAMAccountName": ["MSSQL$"],
                                 "servicePrincipalName": ["MSSQLSvc/sql.sccm.lab:1433"]},
            "native-ldap")
    inv.add("computers", "S-2", {"name": ["MECM"], "dNSHostName": ["MECM.sccm.lab"]}, "native-ldap")
    raw = {"sccm": [{"distinguishedName": "CN=SMS-MP-P01-MECM.SCCM.LAB,CN=System Management,DC=sccm,DC=lab",
                     "cn": ["SMS-MP-P01-MECM.SCCM.LAB"],
                     "objectClass": ["top", "mSSMSManagementPoint"],
                     "dNSHostName": ["MECM.sccm.lab"]}]}

    result = discover(inv, raw)

    hosts = {host["name"]: host for host in result["hosts"]}
    assert hosts["MSSQL"]["fqdn"] == "MSSQL.sccm.lab"
    assert result["sql_servers"][0]["name"] == "MSSQL"
    assert hosts["MECM"]["role"] == "confirmed-sccm-published-host"


def test_relayking_is_detectable_from_checkout(monkeypatch, tmp_path):
    monkeypatch.setattr("ad_enum.core.planner.__file__", str(tmp_path / "ad_enum/core/planner.py"))
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


def test_sccm_publication_normalizes_site_and_management_point():
    inv = DomainInventory()
    inv.add("computers", "S-1", {"name": "MECM", "dNSHostName": "MECM.sccm.lab"}, "native-ldap")
    raw = {"sccm": [
        {"distinguishedName": "CN=SMS-Site-P01,CN=System Management,DC=sccm,DC=lab",
         "cn": ["SMS-Site-P01"], "objectClass": ["top", "mSSMSSite"]},
        {"distinguishedName": "CN=SMS-MP-P01-MECM.SCCM.LAB,CN=System Management,DC=sccm,DC=lab",
         "cn": ["SMS-MP-P01-MECM.SCCM.LAB"], "objectClass": ["top", "mSSMSManagementPoint"],
         "dNSHostName": ["MECM.sccm.lab"]},
    ]}
    result = discover(inv, raw, {"records": [{"fqdn": "mecm.sccm.lab", "ip_addresses": ["10.1.10.41"]}]})
    assert result["site_code"] == "P01"
    assert result["management_points"][0]["host"] == "MECM.sccm.lab"
    assert result["management_points"][0]["confidence"] == "confirmed"
    assert result["management_points"][0]["ip_addresses"] == ["10.1.10.41"]


def test_sccm_publication_dedupes_endpoint_records():
    from ad_enum.sccm import parse_sccm_publication
    obj = {"distinguishedName": "CN=MP", "cn": ["SMS-MP-P01-MECM.SCCM.LAB"],
           "objectClass": ["mSSMSManagementPoint"], "dNSHostName": ["MECM.sccm.lab"]}
    result = parse_sccm_publication([obj, obj])
    assert len(result["endpoints"]) == 1


def test_sccm_mp_probe_parses_metadata_without_retaining_key_material(monkeypatch):
    from ad_enum.sccm import probe_management_points

    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit):
            return b'<MPList><MP Name="MECM.SCCM.LAB" FQDN="MECM.sccm.lab"><Version>9128</Version></MP></MPList>'

    monkeypatch.setattr("ad_enum.sccm.urllib.request.urlopen", lambda request, timeout: Response())
    result = probe_management_points([{"host": "MECM.sccm.lab", "fqdn": "MECM.sccm.lab"}], 1)
    assert result[0]["status"] == "CONFIRMED"
    assert result[0]["metadata"]["fqdn"] == "MECM.sccm.lab"
    assert "body" not in result[0]


def test_relayking_paths_are_normalized_without_action_fields():
    result = normalize_relayking({"statistics": {"relayable_hosts": 1}, "relay_paths": [
        {"source_host": "MECM", "dest_host": "DC", "dest_protocol": "ldap",
         "impact": "HIGH", "description": "observed", "coerce": True} ]})
    assert result["statistics"]["relayable_hosts"] == 1
    assert result["paths"][0]["dest_protocol"] == "ldap"
    assert "coerce" not in result["paths"][0]
