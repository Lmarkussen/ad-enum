from ad_enum.inventory import DomainInventory
from ad_enum.recon import (build_privilege_paths, normalize_dfs, normalize_mssql,
                            normalize_services, normalize_trust_context)


def test_mssql_instances_are_candidates_and_keep_sccm_context():
    inventory = DomainInventory()
    inventory.add("computers", "S-1", {
        "name": "MSSQL", "dNSHostName": "mssql.sccm.lab",
        "sAMAccountName": "svc-sql$",
        "servicePrincipalName": ["MSSQLSvc/mssql.sccm.lab:1433", "MSSQLSvc/mssql.sccm.lab:51433"],
    }, "native-ldap")
    result = normalize_mssql(inventory, sccm_relationship={"host": "mssql.sccm.lab",
                                                            "site_code": "P01", "database": "CM_P01",
                                                            "confidence": "PARTIAL"})
    assert [x["port"] for x in result] == [1433, 51433]
    assert result[0]["confidence"] == "CANDIDATE"
    assert result[0]["sccm"]["database"] == "CM_P01"


def test_dfs_and_services_are_bounded_and_deduplicated():
    dfs = normalize_dfs([{"namespace": "\\\\sccm.lab\\Software", "path": "Tools",
                          "targets": ["\\\\FILE01\\Tools$", "\\\\FILE01\\Tools$"],
                          "access": "readable"}])
    assert dfs[0]["targets"] == ["\\\\FILE01\\Tools$"]
    services = normalize_services([{"host": "MECM", "ip": "10.1.10.41",
                                    "services": [{"name": "WinRM", "port": 5985, "state": "open"},
                                                  {"name": "WinRM", "port": 5985, "state": "open"}]}])
    assert len(services) == 1
    assert services[0]["state"] == "OPEN"


def test_trust_context_and_privilege_paths_preserve_sources_and_depth():
    trusts = normalize_trust_context([{"trustPartner": ["child.example"], "trustDirection": [3],
                                      "trustType": [2], "trustAttributes": [8]}])
    assert trusts[0]["direction"] == "BIDIRECTIONAL"
    assert trusts[0]["trust_type"] == "UPLEVEL"
    edges = [{"source": "user", "target": "group", "type": "MEMBER_OF", "sources": ["LDAP"]},
             {"source": "group", "target": "gpo", "type": "CAN_MODIFY_GPO", "high_value": True,
              "sources": ["ACL", "GPO"]}]
    paths = build_privilege_paths(edges, max_edges=3)
    assert paths[0]["nodes"] == ["user", "group", "gpo"]
    assert paths[0]["sources"] == ["ACL", "GPO", "LDAP"]
