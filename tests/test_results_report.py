import copy
import json

from ad_enum.cli import (_access_summary_lines, _compact_field_lines, _cred1_summary_lines,
                         _finding_detail_lines, _finding_lines, _results_text,
                         _service_summary_lines, _smb_share_access_lines)
from ad_enum.core.console import Console
from ad_enum.core.workspace import ScanWorkspace
from ad_enum.inventory import DomainInventory
from ad_enum.kerberos import ad_filetime, account_security_context, account_exposure
from ad_enum.inventory import InventoryRecord
from io import StringIO


def _report(tmp_path, findings):
    workspace = ScanWorkspace(tmp_path, "sccm.lab", scan_id="scan-one")
    return _results_text("SCCM.LAB", "dc.sccm.lab", {}, DomainInventory(), [], [],
                         findings, workspace, corroborated=1, disagreements=0)


class TTY(StringIO):
    def isatty(self):
        return True


def test_results_report_contains_consolidated_group_and_target_secret(tmp_path):
    report = _report(tmp_path, [{"category": "GPO", "rule": "gpo-script-credential",
        "title": "Cleartext credential — ADEnum-GPO-Test", "affected_object": "gpo",
        "status": "single-source", "evidence": {"file": "startup.ps1", "account": "fixture",
        "type": "PowerShell literal", "value": "SyntheticOnly-123!"}}])
    assert "Target" in report
    assert "------------[ GPO ]------------" in report
    assert "SyntheticOnly-123!" in report
    assert "[GPO]" not in report.split("------------[ GPO ]------------", 1)[1].splitlines()[2]
    assert "\x1b[" not in report


def test_results_report_shows_normalized_smb_share_access(tmp_path):
    report = _results_text("SCCM.LAB", "dc.sccm.lab", {}, DomainInventory(), [], [], [],
                           ScanWorkspace(tmp_path, "sccm.lab"), smb_shares=[
                               {"host": "FILE01", "share": "Public", "unc": "\\\\FILE01\\Public", "readable": True, "writable": False},
                               {"host": "FILE01", "share": "Deploy$", "unc": "\\\\FILE01\\Deploy$", "readable": True, "writable": True},
                               {"host": "FILE01", "share": "Finance", "unc": "\\\\FILE01\\Finance", "readable": False, "writable": False},
                               {"host": "FILE01", "share": "Unknown", "unc": "\\\\FILE01\\Unknown"},
                               ])
    assert "SMB Share Access" in report
    assert "FILE01\\Public" in report and "READ" in report
    assert "FILE01\\Deploy$" in report and "READ / WRITE" in report
    assert "FILE01\\Finance" in report and "DENIED" in report
    assert "FILE01\\Unknown" in report and "UNKNOWN" in report


def test_smb_share_access_is_grouped_and_sorted(tmp_path):
    shares = [
        {"host": "MSSQL", "share": "IPC$", "unc": r"\\MSSQL\IPC$", "readable": True},
        {"host": "DC", "share": "SYSVOL", "unc": r"\\DC\SYSVOL", "readable": True},
        {"host": "CLIENT", "share": "C$", "unc": r"\\CLIENT\C$", "readable": True, "writable": True},
        {"host": "MECM", "share": "share_iso", "unc": r"\\MECM\share_iso", "readable": True, "writable": True},
        {"host": "DC", "share": "IPC$", "unc": r"\\DC\IPC$", "readable": True},
        {"host": "CLIENT", "share": "ADMIN$", "unc": r"\\CLIENT\ADMIN$", "readable": True, "writable": True},
        {"host": "DC", "share": "NETLOGON", "unc": r"\\DC\NETLOGON", "readable": True},
    ]
    report = _results_text("SCCM.LAB", "dc.sccm.lab", {}, DomainInventory(), [], [], [],
                           ScanWorkspace(tmp_path, "sccm.lab"), smb_shares=shares)
    section = report.split("SMB Share Access\n", 1)[1].split("\nFindings", 1)[0]

    assert section.index("Writable non-admin shares") < section.index("Administrative shares")
    assert section.index("Administrative shares") < section.index("Other accessible shares")
    assert "CLIENT\\ADMIN$" not in section.split("Administrative shares", 1)[0]
    assert "CLIENT\\C$" not in section.split("Administrative shares", 1)[0]
    assert section.index(r"MECM\share_iso") < section.index(r"CLIENT\ADMIN$")
    assert section.index(r"CLIENT\ADMIN$") < section.index(r"CLIENT\C$")
    assert section.index(r"CLIENT\C$") < section.index(r"DC\IPC$")
    assert section.index(r"DC\IPC$") < section.index(r"DC\NETLOGON")
    assert section.index(r"DC\NETLOGON") < section.index(r"DC\SYSVOL")
    assert "Path ............." not in section
    assert "MECM\\share_iso" in section and "READ / WRITE" in section
    assert shares[3]["unc"] == r"\\MECM\share_iso"


def test_smb_share_access_preserves_nonstandard_paths_and_omits_empty_groups(tmp_path):
    shares = [{"host": "FILE01", "share": "Deploy", "unc": r"\\alias\Deploy", "readable": True}]
    lines = _smb_share_access_lines(shares)
    report = _results_text("EXAMPLE.LOCAL", "dc.example.local", {}, DomainInventory(), [], [], [],
                           ScanWorkspace(tmp_path, "example.local"), smb_shares=shares)
    section = report.split("SMB Share Access\n", 1)[1].split("\nFindings", 1)[0]

    assert lines == [
        "  Other accessible shares",
        "    FILE01\\Deploy  READ",
        r"      Path ............. \\alias\Deploy",
    ]
    assert section.count("Other accessible shares") == 1
    assert "Writable non-admin shares" not in section
    assert "Administrative shares" not in section
    assert "Inaccessible / denied" not in section


def test_smb_share_access_keeps_denied_group_after_accessible_groups(tmp_path):
    shares = [
        {"host": "FILE01", "share": "Denied", "unc": r"\\FILE01\Denied", "readable": False},
        {"host": "FILE01", "share": "Unknown", "unc": r"\\FILE01\Unknown"},
        {"host": "FILE01", "share": "Public", "unc": r"\\FILE01\Public", "readable": True},
    ]
    report = _results_text("EXAMPLE.LOCAL", "dc.example.local", {}, DomainInventory(), [], [], [],
                           ScanWorkspace(tmp_path, "example.local"), smb_shares=shares)
    section = report.split("SMB Share Access\n", 1)[1].split("\nFindings", 1)[0]

    assert section.index("Other accessible shares") < section.index("Inaccessible / denied")
    assert "FILE01\\Denied" in section and "DENIED" in section
    assert "FILE01\\Unknown" in section and "UNKNOWN" in section


def test_smb_share_access_console_and_results_use_the_same_lines(tmp_path):
    shares = [{"host": "MECM", "share": "share_iso", "unc": r"\\MECM\share_iso",
               "readable": True, "writable": True}]
    report = _results_text("SCCM.LAB", "dc.sccm.lab", {}, DomainInventory(), [], [], [],
                           ScanWorkspace(tmp_path, "sccm.lab"), smb_shares=shares)
    console_stream = StringIO()
    console = Console(stream=console_stream, no_color=True)
    console.heading("SMB Share Access")
    for line in _smb_share_access_lines(shares):
        console.line(line)
    console_section = console_stream.getvalue().split("SMB Share Access\n", 1)[1].rstrip("\n")
    report_section = report.split("SMB Share Access\n", 1)[1].split("\nFindings", 1)[0].rstrip("\n")

    assert console_section == report_section


def test_orange_highlights_only_admin_share_access_state():
    console = Console(stream=TTY())
    lines = _smb_share_access_lines([
        {"host": "HOST1", "share": "ADMIN$", "readable": True, "writable": True},
        {"host": "HOST1", "share": "Public", "readable": True, "writable": True},
    ], access_style=console.highlight_admin)
    output = "\n".join(lines)

    assert "\033[38;5;208mREAD / WRITE\033[0m" in output
    assert "HOST1\\ADMIN$" in output
    non_admin = next(line for line in lines if "HOST1\\Public" in line)
    assert "\033[" not in non_admin


def test_orange_highlighting_is_clean_for_non_tty_and_no_color():
    for console in (Console(stream=StringIO()), Console(stream=TTY(), no_color=True)):
        assert console.highlight_secret("ExampleRecoveredSecret") == "ExampleRecoveredSecret"
        assert console.highlight_admin("[ADMIN]") == "[ADMIN]"


def test_orange_highlights_only_explicit_admin_marker():
    console = Console(stream=TTY())
    lines = _access_summary_lines([
        {"host": "dc1.example.test", "protocol": "RDP",
         "authentication": "AUTHENTICATED", "privilege": "ADMIN"},
        {"host": "dc1.example.test", "protocol": "LDAP",
         "authentication": "AUTHENTICATED", "privilege": "STANDARD"},
    ], admin_style=console.highlight_admin)
    output = "\n".join(lines)

    assert "AUTHENTICATED   \033[38;5;208m[ADMIN]\033[0m" in output
    assert "\033[38;5;208mAUTHENTICATED" not in output
    assert "LDAP  AUTHENTICATED" in output


def test_recovered_secret_value_is_orange_but_labels_are_not():
    console = Console(stream=TTY())
    cred_lines = _cred1_summary_lines({
        "dp": "192.0.2.41", "credentials": [{"type": "variable", "name": "ExampleVariable",
                                                "value": "ExampleRecoveredSecret"}],
    }, secret_style=console.highlight_secret)
    finding_lines = _finding_detail_lines({
        "rule": "gpo-cleartext-credential", "evidence": {
            "type": "net use", "value": "AnotherExampleSecret",
        },
    }, secret_style=console.highlight_secret)
    output = "\n".join(cred_lines + finding_lines)

    assert "Password  \033[38;5;208mExampleRecoveredSecret\033[0m" in output
    assert "Value  \033[38;5;208mAnotherExampleSecret\033[0m" in output
    assert "\033[38;5;208mPassword" not in output
    assert "\033[38;5;208mValue" not in output


def test_target_collectors_inventory_results_are_clean_aligned_fields(tmp_path):
    inventory = DomainInventory()
    for kind, count in (("users", 2), ("groups", 3), ("computers", 1),
                        ("domain_controllers", 1), ("domains", 1)):
        for index in range(count):
            inventory.add(kind, f"{kind}-{index}")
    report = _results_text(
        "example.test", "192.0.2.10",
        {"bloodhound": {"status": "PASS"}, "adcs-certipy": {"status": "PASS"}},
        inventory, ["CA"], ["Template"], [], ScanWorkspace(tmp_path, "example.test"),
    )
    sections = report.split("Target\n", 1)[1].split("Correlation\n", 1)[0]

    assert "Domain Controller  192.0.2.10" in sections
    assert "BloodHound      PASS" in sections
    assert "Users               2" in sections
    assert "Domain Controllers  1" in sections
    assert "........" not in sections


def test_results_text_never_contains_terminal_ansi_sequences(tmp_path):
    report = _results_text(
        "example.test", "dc1.example.test", {}, DomainInventory(), [], [], [],
        ScanWorkspace(tmp_path, "example.test"),
        smb_shares=[{"host": "HOST1", "share": "ADMIN$", "readable": True, "writable": True}],
        access_records=[{"host": "dc1.example.test", "protocol": "RDP",
                         "authentication": "AUTHENTICATED", "privilege": "ADMIN"}],
        cred1={"dp": "192.0.2.41", "credentials": [{"type": "variable", "name": "ExampleVariable",
                                                       "value": "ExampleRecoveredSecret"}]},
    )

    assert "\033[" not in report


def test_styled_rendering_does_not_mutate_structured_records():
    console = Console(stream=TTY())
    share = {"host": "HOST1", "share": "ADMIN$", "readable": True, "writable": True}
    access = {"host": "dc1.example.test", "protocol": "RDP",
              "authentication": "AUTHENTICATED", "privilege": "ADMIN"}
    cred1 = {"dp": "192.0.2.41", "credentials": [{"type": "variable", "name": "ExampleVariable",
                                                   "value": "ExampleRecoveredSecret"}]}
    original = copy.deepcopy((share, access, cred1))

    _smb_share_access_lines([share], access_style=console.highlight_admin)
    _access_summary_lines([access], admin_style=console.highlight_admin)
    _cred1_summary_lines(cred1, secret_style=console.highlight_secret)

    assert (share, access, cred1) == original
    assert "\033[" not in json.dumps((share, access, cred1))


def test_aggregated_finding_lists_affected_objects(tmp_path):
    finding = {"category": "SMB", "rule": "signing-not-required",
               "title": "SMB signing not required — 3 host(s)", "status": "single-source",
               "evidence": {"hosts": [{"fqdn": "MECM.sccm.lab"},
                                         {"host": "MSSQL.sccm.lab"},
                                         {"ip": "10.1.10.43"}]}}
    report = _report(tmp_path, [finding])
    assert "Affected objects" in report
    assert "MECM.sccm.lab" in report
    assert "MSSQL.sccm.lab" in report
    assert "10.1.10.43" in report


def test_results_report_shows_authenticated_access_without_privilege_inference(tmp_path):
    report = _results_text("SCCM.LAB", "dc.sccm.lab", {}, DomainInventory(), [], [], [],
                           ScanWorkspace(tmp_path, "sccm.lab"), access_records=[
                               {"host": "DC.sccm.lab", "protocol": "SSH",
                                "authentication": "AUTHENTICATED", "privilege": "UNKNOWN"}])
    assert "Authenticated Access" in report
    assert "  DC.sccm.lab\n    SSH  AUTHENTICATED" in report


def test_service_exposure_is_grouped_by_canonical_host_and_sorted():
    identities = {"records": [
        {"fqdn": "dc1.example.test", "short_name": "DC1", "ip_addresses": ["192.0.2.10"]},
        {"fqdn": "client1.example.test", "short_name": "CLIENT1", "ip_addresses": ["192.0.2.11"]},
    ]}
    services = [
        {"host": "DC1", "ip": "192.0.2.10", "service": "SMB", "port": 445,
         "reachable": True, "state": "OPEN", "protocol_state": "TCP OPEN"},
        {"host": "dc1.example.test", "ip": "192.0.2.10", "service": "RDP", "port": 3389,
         "reachable": True, "state": "OPEN", "protocol_state": "NEGOTIATION ERROR"},
        {"host": "DC1.EXAMPLE.TEST", "ip": "192.0.2.10", "service": "RPC", "port": 135,
         "reachable": True, "state": "OPEN", "protocol_state": "TCP OPEN"},
        {"host": "CLIENT1", "ip": "192.0.2.11", "service": "WinRM HTTP", "port": 5985,
         "reachable": True, "state": "OPEN", "protocol_state": "PROTOCOL CONFIRMED"},
        {"host": "client1.example.test", "ip": "192.0.2.11", "service": "HTTPS", "port": 443,
         "reachable": True, "state": "OPEN", "protocol_state": "TLS ERROR"},
    ]
    lines = _service_summary_lines(services, host_identities=identities)

    assert lines == [
        "  client1.example.test",
        "    HTTPS/443        TLS ERROR",
        "    WinRM HTTP/5985  PROTOCOL CONFIRMED",
        "",
        "  dc1.example.test",
        "    RPC/135          TCP OPEN",
        "    SMB/445          TCP OPEN",
        "    RDP/3389         NEGOTIATION ERROR",
    ]
    assert lines.count("  client1.example.test") == 1
    assert lines.count("  dc1.example.test") == 1
    assert {line.strip().split("  ", 1)[0] for line in lines if "/" in line} == {
        "HTTPS/443", "WinRM HTTP/5985", "RPC/135", "SMB/445", "RDP/3389"
    }


def test_authenticated_access_merges_only_evidenced_aliases_and_shows_explicit_admin():
    identities = {"records": [
        {"fqdn": "dc1.example.test", "short_name": "DC1", "ip_addresses": ["192.0.2.10"]},
        {"fqdn": "dc10.example.test", "short_name": "DC10", "ip_addresses": ["192.0.2.12"]},
        {"fqdn": "client1.example.test", "short_name": "CLIENT1", "ip_addresses": ["192.0.2.11"]},
    ]}
    records = [
        {"host": "DC1", "ip": "192.0.2.10", "protocol": "SMB",
         "authentication": "AUTHENTICATED", "privilege": "ADMIN"},
        {"host": "dc1.example.test", "ip": "192.0.2.10", "protocol": "LDAP",
         "authentication": "AUTHENTICATED", "privilege": "UNKNOWN"},
        {"host": "DC1.EXAMPLE.TEST", "ip": "192.0.2.10", "protocol": "RDP",
         "authentication": "AUTHENTICATED", "privilege": "ADMIN"},
        {"host": "DC1", "ip": "192.0.2.10", "protocol": "WINRM",
         "authentication": "AUTHENTICATED", "privilege": "STANDARD"},
        {"host": "CLIENT1", "ip": "192.0.2.11", "protocol": "SMB",
         "authentication": "AUTHENTICATED", "privilege": "UNKNOWN"},
        {"host": "client1.example.test", "ip": "192.0.2.11", "protocol": "RDP",
         "authentication": "AUTHENTICATED", "privilege": "UNKNOWN"},
        {"host": "DC10", "ip": "192.0.2.12", "protocol": "SMB",
         "authentication": "AUTHENTICATED", "privilege": "UNKNOWN"},
        {"host": "dc10.example.test", "ip": "192.0.2.12", "protocol": "RDP",
         "authentication": "AUTHENTICATED", "privilege": "UNKNOWN"},
        {"host": "DC1", "ip": "192.0.2.10", "protocol": "SSH",
         "authentication": "DENIED", "privilege": "ADMIN"},
    ]
    lines = _access_summary_lines(records, host_identities=identities)

    assert lines == [
        "  client1.example.test  (192.0.2.11)",
        "    SMB    AUTHENTICATED",
        "    RDP    AUTHENTICATED",
        "",
        "  dc1.example.test  (192.0.2.10)",
        "    SMB    AUTHENTICATED   [ADMIN]",
        "    LDAP   AUTHENTICATED",
        "    RDP    AUTHENTICATED   [ADMIN]",
        "    WINRM  AUTHENTICATED",
        "",
        "  dc10.example.test  (192.0.2.12)",
        "    SMB    AUTHENTICATED",
        "    RDP    AUTHENTICATED",
    ]
    assert sum("AUTHENTICATED" in line for line in lines) == 8
    assert sum("[ADMIN]" in line for line in lines) == 2
    assert not any("SSH" in line for line in lines)


def test_results_text_uses_grouped_service_and_access_renderers(tmp_path):
    identities = {"records": [{"fqdn": "host1.example.test", "short_name": "HOST1",
                                "ip_addresses": ["192.0.2.20"]}]}
    services = [{"host": "HOST1", "ip": "192.0.2.20", "service": "RPC", "port": 135,
                 "reachable": True, "state": "OPEN", "protocol_state": "TCP OPEN"}]
    access = [{"host": "host1.example.test", "ip": "192.0.2.20", "protocol": "SMB",
               "authentication": "AUTHENTICATED", "privilege": "UNKNOWN"}]
    report = _results_text("EXAMPLE.TEST", "host1.example.test", {}, DomainInventory(), [], [], [],
                           ScanWorkspace(tmp_path, "example.test"), services=services,
                           access_records=access, host_identities=identities)

    assert "Service Exposure\n  host1.example.test\n    RPC/135  TCP OPEN" in report
    assert "Authenticated Access\n  host1.example.test  (192.0.2.20)\n    SMB  AUTHENTICATED" in report


def test_results_report_shows_complete_cred1_finding_credential(tmp_path):
    finding = {"category": "SCCM", "rule": "CRED-1",
               "title": "CRED-1 — PXE boot media exposes credential material",
               "affected_object": "10.0.0.41", "status": "confirmed",
               "evidence": {"dp": "10.0.0.41", "site": "P01", "interface": "eth0",
                            "wds": "CONFIRMED", "boot_var": "RECOVERED",
                            "media_identity": "RECOVERED", "assignment": "RECEIVED",
                            "policies": 5, "unique_secrets": 1,
                            "type": "task_sequence_variable", "name": "SyntheticName",
                            "value": "ADEnum-CRED1-Test-Secret",
                            "source_policy": "Policy-A"}}
    report = _report(tmp_path, [finding])
    assert "Unique secrets" not in report
    assert "Unique secrets ..... 1" not in report
    assert "Recovered credential" in report
    assert "ADEnum-CRED1-Test-Secret" in report
    assert "SyntheticName" in report


def test_cred1_summary_is_grouped_compact_and_preserves_data():
    item = {
        "dp": "192.0.2.41", "site_code": "EX1", "interface": "eth0",
        "wds": "CONFIRMED", "pxe": "CONFIRMED", "tftp": "CONFIRMED",
        "boot_var": "RECOVERED", "media_identity": "RECOVERED",
        "assignment": "RECEIVED", "policies": 5, "boot_file": "UNKNOWN",
        "media_protection": "UNKNOWN", "secret_inspection": "COMPLETE",
        "credentials": [{"type": "task_sequence_variable", "name": "ExampleVariable",
                         "value": "ExampleRecoveredSecret"}],
        "operator_password": "OperatorOnlySecret",
    }
    original = copy.deepcopy(item)
    lines = _cred1_summary_lines(item, width=80)
    output = "\n".join(lines)

    assert "PXE / WDS" in output
    assert "Inspection" in output
    assert "Recovered credential" in output
    assert "ExampleRecoveredSecret" in output
    assert "OperatorOnlySecret" not in output
    assert output.count("Unique secrets") == 1
    assert "...." not in output
    assert item == original


def test_results_text_uses_compact_cred1_renderer(tmp_path):
    report = _results_text(
        "EXAMPLE.TEST", "dc1.example.test", {}, DomainInventory(), [], [], [],
        ScanWorkspace(tmp_path, "example.test"),
        cred1={"dp": "192.0.2.41", "site_code": "EX1", "interface": "eth0",
               "wds": "CONFIRMED", "pxe": "CONFIRMED", "tftp": "CONFIRMED",
               "boot_var": "RECOVERED", "media_identity": "RECOVERED",
               "assignment": "RECEIVED", "policies": 5,
               "boot_file": "UNKNOWN", "media_protection": "UNKNOWN",
               "secret_inspection": "COMPLETE", "credentials": [{
                   "type": "task_sequence_variable", "name": "ExampleVariable",
                   "value": "ExampleRecoveredSecret"}],
        },
    )
    section = report.split("SCCM CRED-1 PXE\n", 1)[1].split("\nFindings", 1)[0]

    assert "  Distribution Point  192.0.2.41" in section
    assert "  PXE / WDS" in section
    assert "  Inspection" in section
    assert "ExampleRecoveredSecret" in section
    assert "...." not in section


def test_finding_details_use_aligned_rows_and_wrap_long_values():
    findings = [
        {"category": "ADCS", "rule": "ESC1", "title": "ESC1 — Example-Template",
         "status": "disagreement", "evidence": {}},
        {"category": "KERBEROS", "rule": "Kerberoastable-account",
         "title": "Kerberoastable — example-user", "status": "corroborated",
         "evidence": {"enabled": True, "spns": ["one", "two"]}},
        {"category": "GPO", "rule": "gpo-script-credential",
         "title": "Cleartext credential in GPO — Example-GPO", "status": "confirmed",
         "evidence": {"file": r"\\example.test\Policies\{123}\Machine\Scripts\Startup\example.cmd",
                      "account": r"EXAMPLE\svc-test", "type": "net use",
                      "value": "ExampleSecret"}},
        {"category": "ACL", "rule": "acl", "title": "ignored",
         "affected_object": "Example-Priv-Group", "status": "confirmed",
         "evidence": {"principal_sid": "S-1-5-21-example",
                      "effective_rights": "ResetPassword, WriteProperty, WriteServicePrincipalName, WriteDacl, WriteOwner"}},
    ]
    original = copy.deepcopy(findings)
    output = "\n".join(_finding_lines(findings, width=72))

    assert "------------[ ADCS ]------------" in output
    assert "------------[ KERBEROS ]------------" in output
    assert "------------[ GPO ]------------" in output
    assert "------------[ ACL ]------------" in output
    assert "Status  CONFIRMED" in output
    assert "Note    Certipy did not classify this template as ESC1" in output
    assert "...." not in output
    assert "WriteServicePrincipalName," in output
    assert "               WriteDacl, WriteOwner" in output
    assert r"\\example.test\Policies\{123}\Machine\Scripts\Startup\examp" in output
    assert "le.cmd" in output
    assert findings == original


def test_simple_findings_remain_compact_and_category_banners_are_preserved():
    output = "\n".join(_finding_lines([
        {"category": "ACCOUNT", "rule": "password-never-expires",
         "title": "Password never expires — example-user", "status": "single-source",
         "evidence": {}},
        {"category": "POLICY", "rule": "password-complexity",
         "title": "Password complexity disabled", "status": "single-source",
         "evidence": {}},
    ]))

    assert "------------[ ACCOUNT ]------------" in output
    assert "------------[ POLICY ]------------" in output
    assert "Password never expires — example-user\n    Status" not in output
    assert "Password complexity disabled\n    Status" not in output
    assert "...." not in output


def test_compact_fields_align_continuations_and_keep_long_paths_complete():
    lines = _compact_field_lines([
        ("Rights", "ResetPassword, WriteProperty, WriteServicePrincipalName, WriteDacl, WriteOwner"),
        ("File", r"\\example.test\Policies\{12345678-1234-1234-1234-123456789012}\Machine\Scripts\Startup\very-long-example.cmd"),
    ], indent="    ", width=60)
    value_column = 4 + len("Rights") + 2

    assert len(lines) > 2
    assert all(line.startswith(" " * value_column) for line in lines[1:2])
    assert "ResetPassword" in "".join(lines)
    assert "very-long-example.cmd" in "".join(line.strip() for line in lines)


def test_console_field_has_one_status_column():
    lines = [Console.field(label, "PASS") for label in
             ("Native LDAP", "BloodHound", "Certipy", "LDAPDomainDump", "NetExec")]
    assert len({line.index("PASS") for line in lines}) == 1


def test_results_report_suppresses_disabled_kerberoast(tmp_path):
    report = _report(tmp_path, [{"category": "KERBEROS", "rule": "Kerberoastable-account",
        "title": "Kerberoastable — disabled (disabled)", "affected_object": "disabled",
        "status": "single-source", "evidence": {"enabled": False}}])
    assert "Kerberoastable — disabled" not in report


def test_each_report_category_has_exactly_one_preceding_blank_line(tmp_path):
    findings = [{"category": "ADCS", "rule": "esc1", "title": "ESC1 — T",
                 "affected_object": "T", "status": "confirmed", "evidence": {}},
                {"category": "POLICY", "rule": "weak", "title": "Weak policy",
                 "affected_object": "domain", "status": "single-source", "evidence": {}},
                {"category": "KERBEROS", "rule": "x", "title": "Kerberoastable — svc",
                 "affected_object": "svc", "status": "corroborated", "evidence": {}}]
    report = _report(tmp_path, findings)
    lines = report.splitlines()
    headers = [i for i, line in enumerate(lines) if line.startswith("------------[")]
    assert [lines[i - 1] for i in headers] == ["", "", ""]
    assert all(i < len(lines) - 1 and lines[i + 1] != "" for i in headers)
    assert "Findings\n\n------------[ ADCS ]------------" in report


def test_terminal_category_header_has_one_blank_line_plain_and_color_modes():
    class TTY(StringIO):
        def isatty(self): return True
    for stream, no_color in ((StringIO(), True), (TTY(), False)):
        console = Console(stream=stream, no_color=no_color)
        console.heading("Findings")
        console.category_header("ADCS")
        console.category_header("POLICY")
        lines = stream.getvalue().splitlines()
        headers = [i for i, line in enumerate(lines) if "------------[" in line]
        assert [lines[i - 1] for i in headers] == ["", ""]


def test_results_write_is_atomic_and_scan_history_can_hold_copy(tmp_path):
    workspace = ScanWorkspace(tmp_path, "example.test", scan_id="scan-one")
    workspace.write_text_atomic(workspace.root / "results.txt", "complete\n")
    workspace.write_text(workspace.history_root / "results.txt",
                         (workspace.root / "results.txt").read_text())
    assert (workspace.root / "results.txt").read_text() == "complete\n"
    assert (workspace.history_root / "results.txt").read_text() == "complete\n"


def test_ad_filetime_and_account_age_are_approximate():
    from datetime import datetime, timezone
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    old = int((now.timestamp() + 11644473600) * 10_000_000)
    assert ad_filetime(old) == now
    record = InventoryRecord("users", "S-1-5-21-1", {
        "sAMAccountName": "admin", "userAccountControl": 0,
        "pwdLastSet": [str(old)], "lastLogonTimestamp": [str(old)]}, ["native-ldap"])
    context = account_security_context(account_exposure(record), now=now)
    assert context["password_age_days"] == 0
    assert context["last_logon_approximate"] is True
