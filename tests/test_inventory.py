import json
from ad_enum.inventory import DomainInventory, normalize_password_policy, parse_bloodhound, parse_ldapdomaindump, native_inventory, build_targets, parse_netexec_smb, sensitive_description

def test_bloodhound_structured_inventory(tmp_path):
    (tmp_path / "x_users.json").write_text(json.dumps({"data":[{"Properties":{"objectsid":"S-1-1-1","name":"A@D"}}]}))
    (tmp_path / "x_computers.json").write_text(json.dumps({"data":[{"Properties":{"objectid":"C","name":"DC.D"}}]}))
    inv = parse_bloodhound(tmp_path)
    assert inv.counts()["users"] == 1 and inv.counts()["computers"] == 1

def test_ldapdomaindump_user_description_is_retained(tmp_path):
    (tmp_path / "domain_users.json").write_text(json.dumps([{"objectSid":"S-1-2-3","sAMAccountName":"carol","description":"test account"}]))
    inv = parse_ldapdomaindump(tmp_path)
    assert inv.records["users"]["s-1-2-3"].attributes["description"] == "test account"

def test_ldapdomaindump_nested_attributes_and_policy(tmp_path):
    (tmp_path / "domain_users.json").write_text(json.dumps([{"dn": "CN=carol", "attributes": {
        "objectSid": ["S-1-2-4"], "sAMAccountName": ["carol"], "description": ["owner"]}}]))
    (tmp_path / "domain_policy.json").write_text(json.dumps([{"attributes": {
        "minPwdLength": [7], "lockoutThreshold": [5]}}]))
    inv = parse_ldapdomaindump(tmp_path)
    assert inv.records["users"]["s-1-2-4"].attributes["description"] == "owner"
    assert inv.password_policy["values"]["minimum_password_length"] == 7

def test_password_policy_parser_preserves_only_observed_values():
    policy = normalize_password_policy("Minimum password length: 7\nAccount lockout threshold: 5\n")
    assert policy["values"] == {"minimum_password_length":"7", "lockout_threshold":"5"}

def test_inventory_merge_records_multiple_sources():
    a, b = DomainInventory(), DomainInventory()
    a.add("users", "S-1", {"name":"carol"}, "native-ldap")
    b.add("users", "S-1", {"description":"desc"}, "ldapdomaindump")
    a.merge(b)
    r = a.records["users"]["s-1"]
    assert r.sources == ["native-ldap", "ldapdomaindump"] and r.attributes["description"] == "desc"

def test_native_json_encoded_sid_is_stable_for_correlation():
    import base64
    sid = b"not-a-real-sid"
    raw = {"defaultNamingContext": "DC=x,DC=test", "identities": [{
        "objectClass": ["user"], "objectSid": [{"base64": base64.b64encode(sid).decode()}]
    }]}
    # Invalid SID bytes are safely retained as no identifier, never a crash.
    assert native_inventory(raw).counts()["users"] == 0

def test_target_discovery_keeps_unresolved_hosts():
    inv = DomainInventory(); inv.add("computers", "S-1", {"name": "DC", "dNSHostName": "dc.test"}, "native-ldap")
    targets = build_targets(inv, resolver=lambda *a, **k: (_ for _ in ()).throw(OSError("no dns")))
    assert targets[0]["dns_status"] == "FAILED" and targets[0]["hostname"] == "DC"

def test_target_discovery_uses_fqdn_attribute():
    inv = DomainInventory(); inv.add("computers", "S-2", {"name": "MECM", "dNSHostName": "MECM.test"}, "native-ldap")
    targets = build_targets(inv, resolver=lambda host, *a, **k: [(None, None, None, None, ("192.0.2.1", 0))])
    assert targets[0]["fqdn"] == "MECM.test" and targets[0]["ips"] == ["192.0.2.1"]

def test_native_dc_indicators_are_normalized():
    inv = native_inventory({"defaultNamingContext": "DC=x", "identities": [{
        "objectClass": ["computer"], "objectSid": "S-1-2-5", "primaryGroupID": 516,
        "distinguishedName": "CN=DC,OU=Domain Controllers,DC=x", "dNSHostName": "dc.x"
    }]})
    assert inv.counts()["domain_controllers"] == 1

def test_netexec_smb_batch_parser():
    text = "SMB 10.0.0.1 445 DC [*] Windows Server 2019 x64 (name:DC) (domain:test) (signing:True) (SMBv1:None)\nSMB 10.0.0.1 445 DC [+] test\\user:pw (Pwn3d!)"
    result = parse_netexec_smb(text)
    assert result[0]["ip"] == "10.0.0.1" and result[0]["smb_signing"] is True and result[0]["smb_authenticated"] is True

def test_sensitive_description_is_conservative():
    assert sensitive_description("Service account for legacy app") is False
    assert sensitive_description("password = redacted") is True

def test_policy_parser_keeps_password_words_when_secret_matches_keyword():
    assert normalize_password_policy("Minimum password length: 5\n")['values']['minimum_password_length'] == '5'
