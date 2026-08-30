from ad_enum.inventory import DomainInventory
from ad_enum.kerberos import roastable, UAC
from ad_enum.delegation import enumerate_delegation, enumerate_gmsa

def add(inv, name, sid, uac=0, **attrs):
    inv.add("users", sid, {"sAMAccountName": name, "objectSid": sid,
                            "userAccountControl": uac, **attrs}, "native-ldap")

def test_asrep_and_spn_are_grouped_and_disabled_is_distinguished():
    inv = DomainInventory()
    add(inv, "alice", "S-1-5-21-1", UAC["DONT_REQ_PREAUTH"])
    add(inv, "disabled", "S-1-5-21-2", UAC["DONT_REQ_PREAUTH"] | UAC["ACCOUNTDISABLE"])
    add(inv, "svc_sql", "S-1-5-21-3", servicePrincipalName=["MSSQLSvc/sql.example:1433", "HOST/sql"])
    result = roastable(inv)
    assert {x.username for x in result["asrep"]} == {"alice", "disabled"}
    assert result["asrep"][1].enabled is False
    assert len(result["kerberoast"]) == 1
    assert result["kerberoast"][0].spns == ["MSSQLSvc/sql.example:1433", "HOST/sql"]

def test_password_not_required_only_enabled_accounts():
    inv = DomainInventory()
    add(inv, "enabled", "S-1-5-21-4", UAC["PASSWD_NOTREQD"])
    add(inv, "disabled", "S-1-5-21-5", UAC["PASSWD_NOTREQD"] | UAC["ACCOUNTDISABLE"])
    assert [x.username for x in roastable(inv)["password_not_required"]] == ["enabled"]

def test_delegation_normalizes_unconstrained_constrained_and_transition():
    inv = DomainInventory()
    add(inv, "svc", "S-1-5-21-6", UAC["TRUSTED_TO_AUTH_FOR_DELEGATION"],
        **{"msDS-AllowedToDelegateTo": ["cifs/server.example"]})
    records = enumerate_delegation(inv)
    assert len(records) == 1
    assert records[0].kind == "constrained"
    assert records[0].protocol_transition is True

def test_dc_unconstrained_is_marked_expected_and_not_lost():
    inv = DomainInventory()
    inv.add("domain_controllers", "S-1-5-21-7", {"sAMAccountName": "DC$"}, "native-ldap")
    inv.add("computers", "S-1-5-21-7", {"sAMAccountName": "DC$",
                                         "userAccountControl": UAC["TRUSTED_FOR_DELEGATION"]}, "native-ldap")
    records = enumerate_delegation(inv)
    assert records[0].kind == "unconstrained"
    assert records[0].expected_dc is True

def test_gmsa_inventory_never_contains_managed_password():
    inv = DomainInventory()
    inv.add("gmsa", "S-1-5-21-8", {"sAMAccountName": "gmsa$",
                                    "objectClass": ["msDS-GroupManagedServiceAccount"],
                                    "servicePrincipalName": ["HOST/gmsa.example"]}, "native-ldap")
    item = enumerate_gmsa(inv)[0]
    assert item["name"] == "gmsa$"
    assert item["spns"] == ["HOST/gmsa.example"]
    assert "password" not in item
    assert "msDS-ManagedPassword" not in item
