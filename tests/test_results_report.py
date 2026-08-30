from ad_enum.cli import _results_text
from ad_enum.core.console import Console
from ad_enum.core.workspace import ScanWorkspace
from ad_enum.inventory import DomainInventory
from ad_enum.kerberos import ad_filetime, account_security_context, account_exposure
from ad_enum.inventory import InventoryRecord


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


def test_console_field_has_one_status_column():
    lines = [Console.field(label, "PASS") for label in
             ("Native LDAP", "BloodHound", "Certipy", "LDAPDomainDump", "NetExec")]
    assert len({line.index("PASS") for line in lines}) == 1


def test_results_report_suppresses_disabled_kerberoast(tmp_path):
    report = _report(tmp_path, [{"category": "KERBEROS", "rule": "Kerberoastable-account",
        "title": "Kerberoastable — disabled (disabled)", "affected_object": "disabled",
        "status": "single-source", "evidence": {"enabled": False}}])
    assert "Kerberoastable — disabled" not in report


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
