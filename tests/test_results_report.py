from ad_enum.cli import _results_text
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
    assert "Public ........ READ" in report
    assert "Deploy$ ........ READ / WRITE" in report
    assert "Finance ........ DENIED" in report
    assert "Unknown ........ UNKNOWN" in report


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
