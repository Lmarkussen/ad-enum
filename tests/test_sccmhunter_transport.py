"""SCCMHunter must reuse the LDAP transport protection native AD-Enum negotiated."""
import sys
from pathlib import Path

from ad_enum import cli, sccmhunter_adapter as sh
from ad_enum.sccmhunter_adapter import build_command, redact_command

SECRET = "ScannerOnlySecret"


def _command(*, ldaps):
    return build_command("/py", "/sccmhunter.py", domain="sccm.lab", dc_ip="10.1.10.40",
                         username="localuser", password=SECRET, ldaps=ldaps)


def test_plain_ldap_environment_keeps_sccmhunter_on_plain_ldap():
    command = _command(ldaps=False)
    assert "-ldaps" not in command
    assert command[2] == "find"


def test_protected_environment_selects_sccmhunter_ldaps():
    command = _command(ldaps=True)
    assert command.count("-ldaps") == 1
    # It is a bare switch: whatever follows is another option, not its value.
    assert command[command.index("-ldaps") + 1].startswith("-")


def test_sccmhunter_password_stays_redacted_in_both_transports():
    for ldaps in (False, True):
        command = _command(ldaps=ldaps)
        assert command[command.index("-p") + 1] == SECRET
        documented = redact_command(command, SECRET)
        assert SECRET not in documented and "-p <password>" in documented


class _Collector:
    raw = {}
    kerberos_session = None
    negotiated_protection = None

    def __init__(self, *args, **kwargs):
        pass

    def preflight(self):
        return "DC=sccm,DC=lab", "CN=Configuration,DC=sccm,DC=lab"

    def collect(self):
        return "DC=sccm,DC=lab", [], []


def _harness(monkeypatch, tmp_path, *, protection):
    """Run the real orchestration with a stubbed collector/SCCM toolchain."""
    seen = {"sccmhunter": [], "pxe": [], "dp": []}
    _Collector.negotiated_protection = protection
    monkeypatch.setattr(cli, "Collector", _Collector)
    monkeypatch.setattr(cli, "probe_anonymous_ldap", lambda *a, **k: {
        "bind": "DENIED", "rootdse": "DENIED", "domain_data": "DENIED", "sources": ["t"]})
    monkeypatch.setattr(cli, "probe_anonymous_smb", lambda *a, **k: {
        "session": "DENIED", "share_enumeration": "DENIED", "shares": [], "sources": ["t"]})
    monkeypatch.setattr(cli, "collect_sysvol", lambda *a, **k: {"status": "PASS", "files": []})
    monkeypatch.setattr(cli, "collect_netlogon", lambda *a, **k: {"status": "PASS", "files": []})
    monkeypatch.setattr(cli, "discover_sccm", lambda *a, **k: {
        "hosts": [], "management_points": [], "distribution_points": [], "site_servers": [],
        "sms_providers": [], "sql_servers": [], "sup_wsus": [],
        "pxe": {"status": "UNKNOWN"}, "status": "sccm-publication-and-inventory"})
    monkeypatch.setattr(cli, "probe_management_points", lambda *a, **k: [])
    monkeypatch.setattr(cli, "execute_external", lambda *a, **k: ({}, []))
    monkeypatch.setattr(cli, "sccmhunter_capability",
                        lambda *a, **k: {"status": "PASS", "detail": "x"})

    def fake_sccmhunter(domain, dc_ip, username, password, *, timeout=None, workdir=None,
                        ldaps=False, checkout=None):
        seen["sccmhunter"].append({"ldaps": ldaps, "domain": domain})
        return {"status": "PASS", "source": "SCCMHunter", "command": "fixture", "commit": "",
                "site_codes": ["P01"],
                "management_points": [{"host": "mecm.sccm.lab", "site_code": "P01"}],
                "distribution_points": [{"host": "mecm.sccm.lab", "pxe": True}],
                "site_servers": []}

    monkeypatch.setattr(cli, "run_sccmhunter", fake_sccmhunter)
    monkeypatch.setattr(cli, "pxethief_capability", lambda *a, **k: {"status": "PASS", "detail": "x"})

    def fake_pxe(dp, *a, **k):
        seen["pxe"].append(str(dp))
        return {"dp": str(dp), "state": "NOT VULNERABLE", "access": "UNKNOWN", "indexed": 0,
                "downloaded": 0, "interesting": 0, "files": [], "credentials": [],
                "errors": [], "source": "PXEThief", "command": "fixture"}

    monkeypatch.setattr(cli, "run_pxethief", fake_pxe)
    monkeypatch.setattr(cli, "sccmsecrets_capability", lambda *a, **k: {"status": "PASS", "detail": "x"})

    def fake_files(dp, username, password, *, timeout=None, workdir=None, **k):
        seen["dp"].append(str(dp))
        return {"dp": str(dp), "state": "ACCESSIBLE", "access": "AUTHENTICATED", "indexed": 3,
                "downloaded": 1, "interesting": 0, "files": [], "credentials": [],
                "errors": [], "source": "SCCMSecrets", "command": "fixture"}

    monkeypatch.setattr(cli, "run_sccmsecrets_files", fake_files)
    monkeypatch.setattr(sys, "argv", ["ad-enum.py", "-u", "fixture", "-p", "not-a-real-secret",
                                      "-domain", "sccm.lab", "-dc-ip", "192.0.2.10",
                                      "--modules", "adcs", "--output-dir", str(tmp_path),
                                      "--no-color"])
    return seen


def test_plain_native_ldap_runs_sccmhunter_once_without_ldaps(monkeypatch, tmp_path):
    seen = _harness(monkeypatch, tmp_path, protection=None)
    assert cli.main() == 0
    assert seen["sccmhunter"] == [{"ldaps": False, "domain": "sccm.lab"}]
    assert seen["pxe"] == ["mecm.sccm.lab"] and seen["dp"] == ["mecm.sccm.lab"]


def test_starttls_protection_propagates_ldaps_to_sccmhunter(monkeypatch, tmp_path):
    seen = _harness(monkeypatch, tmp_path, protection="starttls")
    assert cli.main() == 0
    assert seen["sccmhunter"] == [{"ldaps": True, "domain": "sccm.lab"}]


def test_ldaps_protection_propagates_ldaps_to_sccmhunter(monkeypatch, tmp_path):
    seen = _harness(monkeypatch, tmp_path, protection="ldaps")
    assert cli.main() == 0
    assert seen["sccmhunter"] == [{"ldaps": True, "domain": "sccm.lab"}]


def test_protected_discovery_still_feeds_pxethief_and_sccmsecrets(monkeypatch, tmp_path):
    seen = _harness(monkeypatch, tmp_path, protection="starttls")
    assert cli.main() == 0
    assert len(seen["sccmhunter"]) == 1  # one execution, no blind retry
    assert seen["pxe"] == ["mecm.sccm.lab"]
    assert seen["dp"] == ["mecm.sccm.lab"]
    rows = (tmp_path / "sccm.lab" / "SCCM" / "inventory.json").read_text()
    assert "mecm.sccm.lab" in rows
