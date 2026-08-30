from ad_enum.network import build_dns_map, parse_networkhound
from ad_enum.gpo import inspect_file, normalize_gpos
from ad_enum.posture import normalize_trusts, normalize_laps
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
