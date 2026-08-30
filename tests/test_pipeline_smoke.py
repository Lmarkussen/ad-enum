import sys

from ad_enum import cli


class FakeCollector:
    raw = {}
    kerberos_session = None

    def __init__(self, *args, **kwargs):
        pass

    def preflight(self):
        return "DC=sccm,DC=lab", "CN=Configuration,DC=sccm,DC=lab"

    def collect(self):
        return "DC=sccm,DC=lab", [], []


def configure_pipeline(monkeypatch, tmp_path, sccm_discovery):
    monkeypatch.setattr(cli, "Collector", FakeCollector)
    monkeypatch.setattr(cli, "probe_anonymous_ldap", lambda *args, **kwargs: {
        "bind": "DENIED", "rootdse": "DENIED", "domain_data": "DENIED", "sources": ["test"]})
    monkeypatch.setattr(cli, "probe_anonymous_smb", lambda *args, **kwargs: {
        "session": "DENIED", "share_enumeration": "DENIED", "shares": [], "sources": ["test"]})
    monkeypatch.setattr(cli, "collect_sysvol", lambda *args, **kwargs: {"status": "PASS", "files": []})
    monkeypatch.setattr(cli, "collect_netlogon", lambda *args, **kwargs: {"status": "PASS", "files": []})
    monkeypatch.setattr(cli, "discover_sccm", sccm_discovery)
    monkeypatch.setattr(cli, "probe_management_points", lambda *args, **kwargs: [])
    monkeypatch.setattr(sys, "argv", ["ad-enum.py", "-u", "fixture", "-p", "not-a-real-secret",
                                        "-domain", "sccm.lab", "-dc-ip", "10.0.0.40",
                                        "--modules", "adcs", "--output-dir", str(tmp_path), "--no-color"])


def test_main_pipeline_reaches_final_report_with_empty_optional_states(monkeypatch, tmp_path):
    configure_pipeline(monkeypatch, tmp_path, lambda *args, **kwargs: {
        "hosts": [], "management_points": [], "distribution_points": [], "site_servers": [],
        "sms_providers": [], "sql_servers": [], "sup_wsus": [], "pxe": {"status": "NOT TESTED"},
    })
    assert cli.main() == 0
    root = tmp_path / "sccm.lab"
    assert (root / "results.txt").is_file()
    assert (root / "coverage.json").is_file()
    assert (root / "scan.json").read_text().find('"status": "COMPLETE"') >= 0
    assert not list(tmp_path.glob("*.html"))


def test_fatal_post_workspace_error_leaves_scan_incomplete(monkeypatch, tmp_path):
    def fail_sccm(*args, **kwargs):
        raise RuntimeError("fixture orchestration failure")
    configure_pipeline(monkeypatch, tmp_path, fail_sccm)
    try:
        cli.main()
    except RuntimeError as exc:
        assert "fixture orchestration failure" in str(exc)
    else:
        raise AssertionError("fatal fixture error was unexpectedly swallowed")
    scan = (tmp_path / "sccm.lab" / "scan.json").read_text()
    assert '"status": "INCOMPLETE"' in scan
    assert not (tmp_path / "sccm.lab" / "results.txt").exists()
