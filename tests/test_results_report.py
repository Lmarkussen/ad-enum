import copy
import json

from ad_enum.cli import (_access_summary_lines, _acl_detail_lines, _compact_field_lines,
                         _cred1_summary_lines, _finding_detail_lines, _finding_lines, _results_text,
                         _networkhound_summary_lines, _service_summary_lines,
                         _smb_share_access_lines, _write_networkhound_dns_map)
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


def test_networkhound_dns_map_export_and_report_reference_are_compact(tmp_path):
    workspace = ScanWorkspace(tmp_path, "example.test", scan_id="scan-one")
    dns_map = {"records": [
        {"fqdn": "file1.example.test", "short_name": "FILE1", "ip_addresses": ["192.0.2.11"]},
        {"fqdn": "dc1.example.test", "short_name": "DC1", "ip_addresses": ["192.0.2.10"]},
    ]}

    reference = _write_networkhound_dns_map(workspace, dns_map)
    assert reference == "NetworkHound/dns-map.txt"
    assert (workspace.root / reference).read_text() == (
        "192.0.2.10    dc1.example.test    DC1\n"
        "192.0.2.11    file1.example.test    FILE1\n"
    )

    report = _results_text("example.test", "dc1.example.test", {}, DomainInventory(), [], [], [],
                           workspace, host_identities=dns_map,
                           networkhound_map_reference=reference)
    section = report.split("NetworkHound\n", 1)[1].split("\nCorrelation", 1)[0]
    assert "Hosts resolved  2" in section
    assert "DNS map         NetworkHound/dns-map.txt" in section
    assert "file1.example.test" not in section
    assert "192.0.2.11" not in section
    assert "\x1b[" not in report


def test_networkhound_console_header_uses_top_level_heading_style():
    target_stream = TTY()
    networkhound_stream = TTY()
    Console(stream=target_stream).heading("Target")
    Console(stream=networkhound_stream).heading(_networkhound_summary_lines({},)[0])

    assert networkhound_stream.getvalue() == "\033[36mNetworkHound\033[0m\n"
    assert target_stream.getvalue().replace("Target", "NetworkHound") == networkhound_stream.getvalue()


def test_networkhound_large_map_stays_out_of_human_readable_summary(tmp_path):
    workspace = ScanWorkspace(tmp_path, "example.test", scan_id="scan-one")
    records = [{"fqdn": f"host{index:03d}.example.test", "short_name": f"HOST{index:03d}",
                "ip_addresses": [f"198.51.{100 + (index - 1) // 254}.{(index - 1) % 254 + 1}"]}
               for index in range(1, 501)]
    dns_map = {"records": records}

    reference = _write_networkhound_dns_map(workspace, dns_map)
    exported = (workspace.root / reference).read_text().splitlines()
    assert len(exported) == 500
    assert exported[0].startswith("198.51.100.1    host001.example.test")
    assert "host500.example.test" in "\n".join(exported)

    summary = "\n".join(_networkhound_summary_lines(dns_map, map_reference=reference))
    report = _results_text("example.test", "dc1.example.test", {}, DomainInventory(), [], [], [],
                           workspace, host_identities=dns_map,
                           networkhound_map_reference=reference)
    assert "host001.example.test" not in summary
    assert "198.51.100.1" not in summary
    assert "Hosts resolved  500" in report
    assert "NetworkHound/dns-map.txt" in report
    assert "host001.example.test" not in report
    assert "198.51.100.1" not in report


def test_password_policy_uses_display_label_without_changing_category_or_value():
    finding = {"category": "POLICY", "rule": "minimum-password-length",
               "title": "Minimum password length is 5", "affected_object": "example.test",
               "status": "single-source", "evidence": {
                   "canonical": {"minimum_password_length": 5}}}
    original = copy.deepcopy(finding)

    output = "\n".join(_finding_lines([finding]))

    assert "------------[ PASSWORD POLICY ]------------" in output
    assert "Minimum password length — 5" in output
    assert "Minimum password length is 5" not in output
    assert finding == original


def test_ldap_finding_prefers_known_canonical_host_and_keeps_ip():
    identities = {"records": [{"fqdn": "dc1.example.test", "short_name": "DC1",
                                "ip_addresses": ["192.0.2.10"]}]}
    finding = {"category": "LDAP", "rule": "ldap-signing-not-required",
               "title": "LDAP signing not required — 192.0.2.10",
               "affected_object": "192.0.2.10", "status": "single-source",
               "evidence": {"state": "NOT REQUIRED",
                            "impact": "LDAP signing enforcement is not required"}}

    output = "\n".join(_finding_lines([finding], host_identities=identities))

    assert "LDAP signing not required — dc1.example.test" in output
    assert "Target              192.0.2.10" in output
    assert "Impact              LDAP signing enforcement is not required" in output
    assert finding["affected_object"] == "192.0.2.10"


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


def test_smb_findings_are_grouped_without_losing_hosts_or_access_state():
    findings = [
        {"category": "SMB", "rule": "signing-not-required",
         "title": "SMB signing not required — 3 host(s)", "status": "single-source",
         "evidence": {"hosts": [{"host": "MECM"}, {"host": "CLIENT"}, {"host": "MSSQL"}]}},
        {"category": "SMB", "rule": "writable-share", "title": "Writable SMB share — MECM\\share_iso",
         "status": "single-source", "evidence": {"share": {
             "host": "MECM", "share": "share_iso", "readable": True, "writable": True}}},
        {"category": "SMB", "rule": "writable-share", "title": "Writable SMB share — DC\\NETLOGON",
         "status": "single-source", "evidence": {"share": {
             "host": "DC", "share": "NETLOGON", "readable": True, "writable": True}}},
    ]
    original = copy.deepcopy(findings)

    output = "\n".join(_finding_lines(findings))

    assert "SMB signing not required\n    Hosts               3\n    Affected" in output
    assert output.index("CLIENT") < output.index("MECM") < output.index("MSSQL")
    assert "Writable SMB shares" in output
    assert "MECM\\share_iso  READ / WRITE" in output
    assert "DC\\NETLOGON     READ / WRITE" in output
    assert "Writable SMB share —" not in output
    assert findings == original


def test_relay_findings_are_grouped_by_protocol_and_signing_candidate():
    identities = {"records": [
        {"fqdn": "dc.example.test", "short_name": "DC", "ip_addresses": ["192.0.2.10"]},
        {"fqdn": "mecm.example.test", "short_name": "MECM", "ip_addresses": ["192.0.2.11"]},
    ]}
    findings = [
        {"category": "RELAY", "rule": "relay-path",
         "title": "Potential NTLM relay path — MECM (smb)", "status": "single-source",
         "affected_object": "MECM", "evidence": {"dest_host": "MECM", "dest_protocol": "smb"}},
        {"category": "RELAY", "rule": "relay-path",
         "title": "Potential NTLM relay path — DC (ldap)", "status": "single-source",
         "affected_object": "DC", "evidence": {"dest_host": "DC", "dest_protocol": "ldap"}},
        {"category": "RELAY", "rule": "relay-path",
         "title": "Potential NTLM relay path — SQL (mssql)", "status": "single-source",
         "affected_object": "SQL", "evidence": {"dest_host": "SQL", "dest_protocol": "mssql"}},
        {"category": "RELAY", "rule": "relay-path",
         "title": "Potential NTLM relay path — MECM (http)", "status": "single-source",
         "affected_object": "MECM", "evidence": {"dest_host": "MECM", "dest_protocol": "http"}},
        {"category": "RELAY", "rule": "SMB-signing-not-required",
         "title": "SMB signing not required — MECM", "status": "single-source",
         "evidence": {"host": {"host": "MECM"}}},
    ]
    original = copy.deepcopy(findings)

    output = "\n".join(_finding_lines(findings, host_identities=identities))

    assert "Potential NTLM relay paths" in output
    assert output.index("    HTTP") < output.index("    LDAP") < output.index("    MSSQL") < output.index("    SMB")
    assert "    SMB — signing not required" in output
    assert "mecm.example.test" in output
    assert "SMB relay candidates" not in output
    assert "Signing not required" not in output
    assert "Potential NTLM relay path —" not in output
    assert findings == original


def test_sccm_finding_summary_omits_repeated_secret_and_keeps_dedicated_section(tmp_path):
    finding = {"category": "SCCM", "rule": "CRED-1",
               "title": "CRED-1 — PXE boot media exposes credential material",
               "affected_object": "192.0.2.41", "status": "confirmed",
               "evidence": {"dp": "192.0.2.41", "site": "P01", "unique_secrets": 1,
                            "value": "ExampleRecoveredSecret"}}
    dedicated = {"dp": "192.0.2.41", "site_code": "P01", "credentials": [{
        "type": "task_sequence_variable", "name": "ExampleVariable",
        "value": "ExampleRecoveredSecret"}]}
    report = _results_text("example.test", "dc1.example.test", {}, DomainInventory(), [], [],
                           [finding], ScanWorkspace(tmp_path, "example.test"), cred1=dedicated)
    findings_section = report.split("Findings\n", 1)[1]

    assert "------------[ SCCM ]------------" in findings_section
    assert "Status              CONFIRMED" in findings_section
    assert "Distribution Point  192.0.2.41" in findings_section
    assert "Site                P01" in findings_section
    assert "Secrets             1" in findings_section
    assert "ExampleRecoveredSecret" not in findings_section
    assert report.count("ExampleRecoveredSecret") == 1


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
        assert console.highlight_control("ResetPassword") == "ResetPassword"
        assert console.finding_title("ESC1 — Example-Template") == "ESC1 — Example-Template"


def test_finding_titles_share_yellow_style_and_details_remain_plain():
    console = Console(stream=TTY())
    titles = [
        "ESC1 — Example-Template",
        "ESC7 — Example-CA",
        "AS-REP roastable — example-user",
        "Cleartext credential in GPO — Example-GPO",
        "Group control — Example-Group",
        r"Writable SMB share — FILE01\Share",
        "CRED-1 — PXE boot media exposes credential material",
        "Password complexity disabled",
    ]

    rendered = [console.finding_title(f"  {title}") for title in titles]

    assert all(line.startswith("\033[33m  ") and line.endswith("\033[0m") for line in rendered)
    assert all("\033[38;5;208m" not in line for line in rendered)

    plain_findings = _finding_lines([{
        "category": "ADCS", "rule": "ESC1", "title": "ESC1 — Example-Template",
        "status": "confirmed", "evidence": {"template": "Example-Template"},
    }])
    assert "\033[" not in "\n".join(plain_findings)


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
    assert "Affected" in report
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
    report = _results_text(
        "SCCM.LAB", "dc.sccm.lab", {}, DomainInventory(), [], [], [finding],
        ScanWorkspace(tmp_path, "sccm.lab"),
        cred1={"dp": "10.0.0.41", "site_code": "P01", "credentials": [{
            "type": "task_sequence_variable", "name": "SyntheticName",
            "value": "ADEnum-CRED1-Test-Secret"}]},
    )
    findings_section = report.split("Findings\n", 1)[1]
    assert "Unique secrets" not in findings_section
    assert "Unique secrets ..... 1" not in findings_section
    assert "Recovered credential" in report
    assert report.count("ADEnum-CRED1-Test-Secret") == 1
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
         "status": "disagreement", "evidence": {
             "certipy_template_enumeration": "AVAILABLE",
             "certipy_template_evaluated": True, "certipy_esc1": False,
         }},
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
    assert "Status                     CONFIRMED" in output
    assert "Note                       Certipy did not classify this template as" in output
    assert "...." not in output
    assert "WriteServicePrincipalName  KERBEROS CONTROL" in output
    assert "WriteDacl                  PERMISSION TAKEOVER" in output
    assert "WriteOwner                 OWNERSHIP TAKEOVER" in output
    assert r"\\example.test\Policies\{123}\Machine\Scripts\Startup\examp" in output
    assert "le.cmd" in output
    assert findings == original


def test_kerberos_titles_and_details_separate_state_and_preauth():
    findings = [
        {"category": "KERBEROS", "rule": "AS-REP-roastable",
         "title": "AS-REP roastable — example-asrep (enabled)",
         "status": "single-source", "evidence": {
             "enabled": True, "preauthentication_required": False}},
        {"category": "KERBEROS", "rule": "Kerberoastable-account",
         "title": "Kerberoastable — svc-sql (enabled)", "status": "corroborated",
         "evidence": {"enabled": True, "spns": ["MSSQLSvc/sql.example.test:1433",
                                                  "HOST/sql.example.test"]}},
    ]

    output = "\n".join(_finding_lines(findings))

    assert "AS-REP roastable — example-asrep (enabled)" not in output
    assert "AS-REP roastable — example-asrep\n    State               enabled\n    Pre-auth            NOT REQUIRED" in output
    assert "Kerberoastable — svc-sql (enabled)" not in output
    assert "Kerberoastable — svc-sql\n    State               enabled\n    SPNs                2\n    Status              CORROBORATED" in output


def test_delegation_renderer_surfaces_state_services_impact_and_rbcd_identity(tmp_path):
    inventory = DomainInventory()
    inventory.add("users", "S-1-5-21-rbcd", {
        "sAMAccountName": "rbcd-user", "domain": "EXAMPLE", "objectClass": ["user"]})
    findings = [
        {"category": "DELEGATION", "rule": "unconstrained",
         "title": "Unconstrained delegation — example-unconst", "status": "single-source",
         "evidence": {"target": "example-unconst", "enabled": True}},
        {"category": "DELEGATION", "rule": "constrained",
         "title": "Constrained + protocol transition — example-const", "status": "single-source",
         "evidence": {"target": "example-const", "enabled": True,
                      "targets": ["cifs/server.example.test", "http/server.example.test"]}},
        {"category": "DELEGATION", "rule": "rbcd", "title": "RBCD — CLIENT01$", "status": "single-source",
         "evidence": {"target": "CLIENT01$", "enabled": True,
                      "principals": [{"sid": "S-1-5-21-rbcd", "name": "S-1-5-21-rbcd"}],
                      "impact": "allowed principal may impersonate users to services on the target"}},
    ]
    original = copy.deepcopy(findings)

    output = "\n".join(_finding_lines(findings, inventory=inventory))
    report = _results_text("example.test", "dc1.example.test", {}, inventory, [], [], findings,
                           ScanWorkspace(tmp_path, "example.test"))

    assert "Unconstrained delegation — example-unconst\n    State               enabled" in output
    assert "Host/account may receive delegated Kerberos credentials" in output
    assert "Constrained + protocol transition — example-const\n    State               enabled" in output
    assert "    Services\n      cifs/server.example.test\n      http/server.example.test" in output
    assert "Can impersonate users to configured Kerberos services" in output
    assert "RBCD — CLIENT01$\n    Allowed principal   EXAMPLE\\rbcd-user" in output
    assert "Principal SID       S-1-5-21-rbcd" in output
    assert "Target              CLIENT01$" in output
    assert "Allowed principal may impersonate users to services on the target" in output
    assert "\033[" not in report
    assert findings == original


def test_delegation_renderer_keeps_unresolved_rbcd_sid():
    finding = {"category": "DELEGATION", "rule": "rbcd", "title": "RBCD — CLIENT01$",
               "status": "single-source", "evidence": {
                   "target": "CLIENT01$", "enabled": True,
                   "principals": [{"sid": "S-1-5-21-unknown", "name": "S-1-5-21-unknown"}]}}

    output = "\n".join(_finding_lines([finding]))

    assert "Allowed principal   S-1-5-21-unknown" in output
    assert "Principal SID       S-1-5-21-unknown" in output
    assert "Allowed principal  unknown" not in output
    assert "orange" not in output.lower()


def _acl_inventory():
    inventory = DomainInventory()
    inventory.add("groups", "S-1-5-21-group", {
        "sAMAccountName": "Example-Priv-Group", "objectClass": ["group"]})
    inventory.add("users", "S-1-5-21-user", {
        "sAMAccountName": "some-principal", "domain": "EXAMPLE",
        "objectClass": ["user"]})
    return inventory


def test_acl_renderer_resolves_principal_and_distinguishes_group_and_account():
    inventory = _acl_inventory()
    findings = [
        {"category": "ACL", "rule": "high-value-right", "title": "ignored",
         "affected_object": "Example-Priv-Group", "evidence": {
             "principal_sid": "S-1-5-21-user", "effective_rights": "WriteProperty, ModifyGroupMembership"}},
        {"category": "ACL", "rule": "high-value-right", "title": "ignored",
         "affected_object": "example-user", "evidence": {
             "principal_sid": "S-1-5-21-user", "effective_rights": "ResetPassword"}},
    ]
    inventory.add("users", "S-1-5-21-account", {
        "sAMAccountName": "example-user", "objectClass": ["user"]})

    output = "\n".join(_finding_lines(findings, inventory=inventory))

    assert "Group control — Example-Priv-Group" in output
    assert "Account control — example-user" in output
    assert "Principal           EXAMPLE\\some-principal" in output
    assert "Principal SID       S-1-5-21-user" in output
    assert "ModifyGroupMembership      DIRECT CONTROL" in output
    assert "WriteProperty              ATTRIBUTE CONTROL" in output
    assert "Impact              Can modify target group membership" in output
    assert "Impact              Effective control of target account is possible" in output


def test_acl_renderer_orders_rights_and_colors_only_direct_control_primitives():
    finding = {"category": "ACL", "rule": "high-value-right", "title": "ignored",
               "affected_object": "example-user", "evidence": {
                   "principal_sid": "S-1-5-21-unresolved",
                   "effective_rights": "WriteProperty, GenericWrite, AllExtendedRights, "
                                       "ModifyGroupMembership, WriteOwner, WriteDacl, GenericAll, ResetPassword"}}
    console = Console(stream=TTY())
    lines = _acl_detail_lines(finding, direct_style=console.highlight_control)
    output = "\n".join(lines)
    ordered = ["ResetPassword", "GenericAll", "WriteDacl", "WriteOwner",
               "ModifyGroupMembership", "WriteProperty", "GenericWrite", "AllExtendedRights"]
    positions = [output.index(right) for right in ordered]

    assert positions == sorted(positions)
    for right in ("ResetPassword", "GenericAll", "WriteDacl", "WriteOwner", "ModifyGroupMembership"):
        assert f"\033[38;5;208m{right}\033[0m" in output
    for right in ("WriteProperty", "WriteServicePrincipalName", "GenericWrite", "AllExtendedRights"):
        assert f"\033[38;5;208m{right}\033[0m" not in output
    assert "WriteProperty              ATTRIBUTE CONTROL" in output
    assert "GenericWrite               BROAD WRITE CONTROL" in output
    assert "AllExtendedRights          EXTENDED CONTROL" in output


def test_acl_renderer_keeps_unresolved_sid_and_results_plain_text(tmp_path):
    finding = {"category": "ACL", "rule": "high-value-right", "title": "ignored",
               "affected_object": "unknown-target", "evidence": {
                   "principal_sid": "S-1-5-21-unknown", "effective_rights": "WriteDacl"}}
    original = copy.deepcopy(finding)
    report = _results_text("example.test", "dc1.example.test", {}, DomainInventory(), [], [],
                           [finding], ScanWorkspace(tmp_path, "example.test"))

    assert "Principal           S-1-5-21-unknown" in report
    assert "Principal SID       S-1-5-21-unknown" in report
    assert "WriteDacl                  PERMISSION TAKEOVER" in report
    assert "\033[" not in report
    assert finding == original


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
    assert "------------[ PASSWORD POLICY ]------------" in output
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
