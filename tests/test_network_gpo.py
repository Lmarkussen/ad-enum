from ad_enum.network import build_dns_map, parse_networkhound
from ad_enum.gpo import inspect_file, normalize_gpos
from ad_enum.posture import (normalize_trusts, normalize_laps, normalize_gpo_links,
                             attach_gpo_links, analyze_effective_acls)
from ad_enum.inventory import DomainInventory


def test_dns_map_merges_sources_and_retains_multiple_ips(monkeypatch):
    inv = DomainInventory()
    inv.add("computers", "S-1", {"dNSHostName": "mecm.sccm.lab", "distinguishedName": "CN=MECM"}, "native-ldap")
    resolver = lambda host, port, type: [(None, None, None, None, ("10.1.10.41", port))]
    result = build_dns_map(inv, {"records": [{"fqdn": "MECM.SCCM.LAB", "ip_addresses": ["10.1.10.42"]}]}, resolver)
    item = result["records"][0]
    assert item["ip_addresses"] == ["10.1.10.41", "10.1.10.42"]
    assert "native-ldap" in item["sources"] and "networkhound" in item["sources"]
    assert result["reverse"]["10.1.10.42"] == ["mecm.sccm.lab"]


def test_networkhound_opengraph_normalization():
    result = parse_networkhound({"graph": {"nodes": [{"id": "S-1", "kinds": ["Computer"], "properties": {"ip_addresses": ["10.1.10.41"]}}, {"id": "N-1", "kinds": ["Subnet"], "properties": {"subnet": "10.1.10.0/24"}}], "edges": [{"kind": "LocatedIn", "start": {"value": "S-1"}, "end": {"value": "N-1"}}]}})
    assert result["records"][0]["object_sid"] == "S-1"
    assert result["records"][0]["subnet"] == "10.1.10.0/24"


def test_gpo_metadata_and_cpassword_are_redacted():
    gpo = normalize_gpos([{"name": ["{ABC}"], "displayName": ["Test GPO"], "gPCFileSysPath": ["\\\\sccm.lab\\SYSVOL\\Policies\\{ABC}"]}])[0]
    findings = inspect_file(gpo, "Groups.xml", '<User userName="svc-test" cpassword="SYNTHETIC" />')
    assert findings[0]["rule"] == "gpp-cpassword"
    assert findings[0]["evidence"]["value"] == "<redacted>"
    assert "SYNTHETIC" not in str(findings)


def test_gpo_weak_keyword_is_not_a_finding():
    gpo = {"guid": "{ABC}", "display_name": "Purpose"}
    assert inspect_file(gpo, "comment.txt", "service account for legacy app") == []


def test_gpo_script_credential_pattern_is_detected_without_secret():
    findings = inspect_file({"guid": "{ABC}", "display_name": "Deploy"}, "install.ps1", '$password = "Synthetic-Only"')
    assert findings and findings[0]["rule"] == "gpo-cleartext-credential"
    assert "Synthetic-Only" not in str(findings)


def test_trust_and_laps_normalization_preserve_observed_values():
    trusts = normalize_trusts([{"distinguishedName": "CN=child", "trustPartner": ["child.lab"], "trustDirection": ["3"], "trustAttributes": ["8"]}])
    assert trusts[0]["partner"] == "child.lab"
    inv = DomainInventory()
    inv.add("computers", "S-1", {"sAMAccountName": "PC$", "msLAPS-PasswordExpirationTime": ["1"]}, "native-ldap")
    laps = normalize_laps([{"lDAPDisplayName": ["msLAPS-Password"]}], inv)
    assert laps["families"]["windows"] is True
    assert laps["passwords_retrieved"] is False


def test_gpo_links_parse_scope_options_and_attach():
    links = normalize_gpo_links([{
        "distinguishedName": "OU=Workstations,DC=example,DC=test",
        "targetType": "ou", "gPLink": ["[LDAP://cn={ABC},cn=policies,cn=system,dc=x;0]"],
        "gPOptions": ["0"]}])
    assert links[0]["links"][0]["guid"] == "abc"
    assert links[0]["links"][0]["enabled"] is True
    gpos = attach_gpo_links([{"guid": "{ABC}", "display_name": "Workstations"}], [{
        "distinguishedName": "OU=Workstations,DC=example,DC=test", "targetType": "ou",
        "gPLink": "[LDAP://cn={ABC},cn=policies,cn=system,dc=x;0]", "gPOptions": "0"}])
    assert gpos[0]["scope"]["targets"] == ["OU=Workstations,DC=example,DC=test"]


def test_gpo_link_disabled_enforced_and_block_inheritance_flags():
    result = normalize_gpo_links([{
        "distinguishedName": "DC=example,DC=test", "targetType": "domain",
        "gPLink": "[LDAP://cn={ONE},cn=policies,cn=system,dc=x;1]"
                   "[LDAP://cn={TWO},cn=policies,cn=system,dc=x;2]",
        "gPOptions": "1"}])[0]
    assert result["block_inheritance"] is True
    assert result["links"][0]["enabled"] is False
    assert result["links"][1]["enforced"] is True


def test_effective_gpo_rights_require_low_privilege_and_honor_deny():
    inv = DomainInventory()
    inv.add("users", "S-1-5-21-1-2-3-1101", {
        "sAMAccountName": "alice", "objectClass": ["user"]}, "native-ldap")
    rows = [{"target": "Workstations", "aces": [
        {"sid": "S-1-5-21-1-2-3-1101", "kind": "allow", "mask": 0x40000000,
         "applies_to_object": True},
        {"sid": "S-1-5-21-1-2-3-1101", "kind": "deny", "mask": 0x40000000,
         "applies_to_object": True}]}]
    assert analyze_effective_acls(rows, inv) == []


def test_effective_acl_names_specific_group_reset_and_spn_rights():
    inv = DomainInventory()
    inv.add("users", "S-1-5-21-1-2-3-1101", {"sAMAccountName": "alice", "objectClass": ["user"]}, "native-ldap")
    rows = [{"target": "svc-admin", "object_class": ["user"], "aces": [
        {"sid": "S-1-5-21-1-2-3-1101", "kind": "allow", "mask": 0x100,
         "object_type": "00299570-246d-11d0-a768-00aa006e0529", "applies_to_object": True},
        {"sid": "S-1-5-21-1-2-3-1101", "kind": "allow", "mask": 0x20,
         "object_type": "f3a64788-5306-11d1-a9c5-0000f80367c1", "applies_to_object": True}]}]
    rights = analyze_effective_acls(rows, inv)[0]["effective_rights"]
    assert "ResetPassword" in rights and "WriteServicePrincipalName" in rights


def test_effective_acl_recognizes_windows_generic_composite_masks():
    inv = DomainInventory()
    inv.add("users", "S-1-5-21-1-2-3-1101", {"sAMAccountName": "alice", "objectClass": ["user"]}, "native-ldap")
    rows = [{"target": "GPO", "aces": [{"sid": "S-1-5-21-1-2-3-1101",
        "kind": "allow", "mask": 0x20028, "applies_to_object": True}]}]
    assert "GenericWrite" in analyze_effective_acls(rows, inv)[0]["effective_rights"]
