from ad_enum.dns_enum import decode_dns_record, merge_into_dns_map, normalize_password_settings, normalize_records, normalize_zones
import struct
from ad_enum.gpo import inspect_file, parse_security_settings
from ad_enum.inventory import is_standard_admin_share, parse_netexec_shares


def test_netexec_share_table_is_normalized():
    rows = parse_netexec_shares("SMB 10.0.0.4 host (name:FILE01)\n  Deploy$  READ,WRITE")
    assert rows[0]["unc"] == r"\\FILE01\Deploy$"
    assert rows[0]["readable"] and rows[0]["writable"]


def test_netexec_prefixed_share_table_is_normalized():
    rows = parse_netexec_shares(
        "SMB 10.0.0.41 445 MECM Share Permissions Remark\n"
        "SMB 10.0.0.41 445 MECM share_iso READ,WRITE iso share\n"
        "SMB 10.0.0.41 445 MECM C$ Default share\n"
        "SMB 10.0.0.41 445 MECM IPC$ READ Remote IPC\n")
    assert [(x["share"], x["readable"], x["writable"]) for x in rows] == [
        ("share_iso", True, True), ("IPC$", True, False)]


def test_standard_admin_shares_are_not_low_privilege_findings():
    assert is_standard_admin_share("ADMIN$")
    assert is_standard_admin_share("C$")
    assert not is_standard_admin_share("share_iso")


def test_ad_dns_records_merge_into_existing_map_without_overwrite():
    dns = {"records": [{"fqdn": "dc.lab", "ip_addresses": ["10.0.0.1"],
                        "ipv4_addresses": ["10.0.0.1"], "ipv6_addresses": [],
                        "sources": ["ldap"], "resolution_methods": [], "conflicts": []}]}
    merged = merge_into_dns_map(dns, [{"fqdn": "dc.lab", "type": "A", "value": "10.0.0.2"}])
    assert merged["records"][0]["ip_addresses"] == ["10.0.0.1", "10.0.0.2"]
    assert "ad-dns" in merged["records"][0]["sources"]


def test_ad_dns_zone_and_record_normalizers():
    assert normalize_zones([{"name": ["lab"]}])[0]["name"] == "lab"
    assert normalize_records([{"zone": "lab", "name": "dc", "recordType": "A", "address": "10.0.0.1"}])[0]["value"] == "10.0.0.1"


def test_ad_dns_binary_a_and_srv_records_decode():
    header = lambda length, kind, ttl=300: struct.pack("<HHBBHIII I", length, kind, 5, 0, 0, 1, ttl, 0, 0)
    a = decode_dns_record(header(4, 1) + bytes([10, 0, 0, 40]), "dc", "sccm.lab")
    assert a["type"] == "A" and a["value"] == "10.0.0.40" and a["fqdn"] == "dc.sccm.lab"
    target = b"\x03_ldap\x04_tcp\x00"
    srv = decode_dns_record(header(6 + len(target), 33) + struct.pack("<HHH", 0, 100, 389) + target,
                            "_ldap._tcp", "sccm.lab")
    assert srv["type"] == "SRV" and "389" in srv["value"]


def test_fgpp_normalization_preserves_precedence_and_applies_to():
    row = {"name": ["WeakPSO"], "distinguishedName": "CN=WeakPSO",
           "msDS-PasswordSettingsPrecedence": ["10"], "msDS-MinimumPasswordLength": ["6"],
           "msDS-PSOAppliesTo": ["CN=svc,DC=lab"]}
    pso = normalize_password_settings([row])[0]
    assert pso["settings"]["msDS-MinimumPasswordLength"] == "6"
    assert pso["applies_to"] == ["CN=svc,DC=lab"]


def test_gpo_security_parser_is_targeted():
    settings = parse_security_settings("Machine/GptTmpl.inf", "RequireSecuritySignature=0\nLMCompatibilityLevel=2")
    assert {x["setting"] for x in settings} == {"smb_signing", "ntlm_level"}


def test_gpp_and_cleartext_finding_values_are_preserved():
    rows = inspect_file({"display_name": "Test"}, "Groups.xml", '<User name="fixture" cpassword="SYNTHETIC"/>')
    assert rows[0]["rule"] == "gpp-cpassword"
    assert rows[0]["evidence"]["value"] == "SYNTHETIC"
