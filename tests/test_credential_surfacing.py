"""Recovered TARGET credentials must be visible; scanner secrets must not."""
import json
import sys
from pathlib import Path

from ad_enum import cli
from ad_enum.core.workspace import ScanWorkspace
from ad_enum.inventory import DomainInventory
from ad_enum.sccm_models import normalize_pxe_validation
from test_pipeline_smoke import FakeCollector

SCANNER_SECRET = "ScannerOnlySecret"
TARGET_SECRET = "TargetRecoveredSecret"


def _pxe_finding(recovered, *, recovered_count=None):
    return {"category": "SCCM", "rule": "PXE", "title": "PXE VULNERABLE — mecm.sccm.lab",
            "affected_object": "10.1.10.41", "status": "confirmed",
            "sources": [{"source": "PXEThief", "observed": True}],
            "evidence": {"dp": "10.1.10.41", "site": "P01", "state": "VULNERABLE",
                         "recovered_count": (recovered_count if recovered_count is not None
                                             else len(recovered)),
                         "recovered": recovered, "source": "PXEThief",
                         "credentials_artifact": "sccm.lab/credentials.txt"}}


def _render(findings, tmp_path):
    report = cli._results_text("sccm.lab", "10.1.10.40", {}, DomainInventory(), [], [],
                               findings, ScanWorkspace(tmp_path, "sccm.lab"))
    return report.split("------------[ SCCM ]------------", 1)[1].split("Workspace", 1)[0]


def test_recovered_credential_value_and_account_are_rendered(tmp_path):
    section = _render([_pxe_finding([{"name": "NetworkAccessAccount",
                                      "username": r"SCCMLAB\svc-osd",
                                      "value": TARGET_SECRET}])], tmp_path)

    assert "Recovered credentials" in section
    assert "NetworkAccessAccount" in section
    assert r"SCCMLAB\svc-osd" in section
    assert TARGET_SECRET in section
    assert "Credentials saved to:" in section
    assert "sccm.lab/credentials.txt" in section


def test_credential_without_username_is_shown_cleanly(tmp_path):
    section = _render([_pxe_finding([{"name": "OSDLocalAdminPassword",
                                      "value": TARGET_SECRET}])], tmp_path)

    assert "OSDLocalAdminPassword" in section
    assert "Password" in section and TARGET_SECRET in section
    assert "Account  " not in section  # no fabricated account


def test_non_secret_items_are_not_labelled_password(tmp_path):
    section = _render([_pxe_finding([{"name": "OSDJoinAccount", "value": r"sccm.lab\svc-join"}])],
                      tmp_path)

    assert "OSDJoinAccount" in section and r"sccm.lab\svc-join" in section
    assert "Password" not in section


def test_mixed_result_distinguishes_items_from_credentials(tmp_path):
    recovered = [
        {"name": "NetworkAccessAccount", "username": r"SCCMLAB\svc-naa", "value": TARGET_SECRET},
        {"name": "OSDLocalAdminPassword", "value": "SecondTargetSecret"},
        {"name": "media", "media_file": r"\SMS\variables.dat"},
        {"name": "bcd", "bcd_file": r"\SMS\boot.bcd"},
        {"name": "identifier", "assignment": "RECEIVED"},
    ]
    section = _render([_pxe_finding(recovered)], tmp_path)

    header = section.split("Recovered credentials", 1)[0]
    fields = {}
    for line in header.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            fields[parts[0]] = parts[1].strip()
    assert fields["Recovered"] == "5 items"
    assert fields["Credentials"] == "2"
    assert TARGET_SECRET in section and "SecondTargetSecret" in section
    assert "variables.dat" not in section and "boot.bcd" not in section


def test_large_recovered_set_is_bounded_in_human_output(tmp_path):
    recovered = [{"name": f"OSDSecret{i:02d}", "value": f"TargetSecret{i:02d}"} for i in range(12)]
    section = _render([_pxe_finding(recovered)], tmp_path)

    assert "OSDSecret00" in section and "OSDSecret04" in section
    assert "OSDSecret05" not in section
    assert "7 additional recovered credential(s)" in section
    assert "sccm.lab/credentials.txt" in section


def test_lab_shaped_mix_counts_only_real_secrets(tmp_path):
    # Mirrors the lab: 5 recovered items of which 3 carry secrets and 2 are
    # account identifiers.
    recovered = [
        {"name": "NetworkAccessAccount", "username": r"SCCMLAB\svc-naa", "value": "SecretOne"},
        {"name": "OSDRegisteredUserName", "value": "User"},
        {"name": "OSDLocalAdminPassword", "value": "SecretTwo"},
        {"name": "OSDJoinAccount", "value": r"sccm.lab\svc-join"},
        {"name": "OSDJoinPassword", "value": "SecretThree"},
    ]
    section = _render([_pxe_finding(recovered)], tmp_path)
    header = section.split("Recovered credentials", 1)[0]
    fields = {}
    for line in header.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            fields[parts[0]] = parts[1].strip()

    assert fields["Recovered"] == "5 items"
    assert fields["Credentials"] == "3"
    assert "SecretOne" in section and "SecretThree" in section
    # Account identifiers are still shown, labelled as values not passwords.
    assert r"sccm.lab\svc-join" in section


def _sccm(entries):
    return {"hosts": [], "management_points": [], "distribution_points": list(entries),
            "site_servers": [], "sms_providers": [], "sql_servers": [], "sup_wsus": [],
            "pxe": {"status": "ENABLED"}, "status": "sccm-publication-and-inventory"}


def _harness(monkeypatch, tmp_path, *, pxe_recovered):
    monkeypatch.setattr(cli, "Collector", FakeCollector)
    monkeypatch.setattr(cli, "probe_anonymous_ldap",
                        lambda *a, **k: {"bind": "DENIED", "rootdse": "DENIED",
                                         "domain_data": "DENIED", "sources": ["t"]})
    monkeypatch.setattr(cli, "probe_anonymous_smb",
                        lambda *a, **k: {"session": "DENIED", "share_enumeration": "DENIED",
                                         "shares": [], "sources": ["t"]})
    monkeypatch.setattr(cli, "collect_sysvol", lambda *a, **k: {"status": "PASS", "files": []})
    monkeypatch.setattr(cli, "collect_netlogon", lambda *a, **k: {"status": "PASS", "files": []})
    monkeypatch.setattr(cli, "discover_sccm", lambda *a, **k: _sccm([
        {"fqdn": "mecm.sccm.lab", "ip_addresses": ["10.1.10.41"], "site_code": "P01"}]))
    monkeypatch.setattr(cli, "probe_management_points", lambda *a, **k: [])
    monkeypatch.setattr(cli, "execute_external", lambda *a, **k: ({}, []))
    monkeypatch.setattr(cli, "pxethief_capability", lambda *a, **k: {"status": "PASS", "detail": "x"})
    monkeypatch.setattr(cli, "run_pxethief", lambda dp, *a, **k: normalize_pxe_validation({
        "dp": str(dp), "state": "VULNERABLE", "source": "PXEThief",
        "recovered": list(pxe_recovered)}))
    monkeypatch.setattr(cli, "sccmhunter_capability",
                        lambda *a, **k: {"status": "PASS", "detail": "x"})
    monkeypatch.setattr(cli, "run_sccmhunter", lambda *a, **k: {
        "status": "PASS", "source": "SCCMHunter", "command": "fixture", "commit": "",
        "site_codes": ["P01"], "management_points": [{"host": "mecm.sccm.lab", "site_code": "P01"}],
        "distribution_points": [], "site_servers": []})
    monkeypatch.setattr(cli, "sccmsecrets_capability",
                        lambda *a, **k: {"status": "PASS", "detail": "x"})
    monkeypatch.setattr(cli, "run_sccmsecrets_files", lambda dp, *a, **k: {
        "dp": str(dp), "state": "ACCESSIBLE", "access": "AUTHENTICATED", "indexed": 3,
        "downloaded": 0, "interesting": 0, "files": [], "credentials": [],
        "errors": [], "source": "SCCMSecrets", "command": "fixture"})
    monkeypatch.setattr(sys, "argv", ["ad-enum.py", "-u", "svc-scan", "-p", SCANNER_SECRET,
                                      "-domain", "sccm.lab", "-dc-ip", "10.1.10.40",
                                      "--modules", "adcs", "--output-dir", str(tmp_path),
                                      "--html-out", str(tmp_path / "report.html"), "--no-color"])


def test_target_credential_surfaces_everywhere_and_scanner_secret_never_does(
        monkeypatch, tmp_path, capsys):
    _harness(monkeypatch, tmp_path, pxe_recovered=[
        {"name": "NetworkAccessAccount", "username": r"SCCMLAB\svc-naa", "value": TARGET_SECRET}])

    assert cli.main() == 0
    console = capsys.readouterr().out
    root = tmp_path / "sccm.lab"
    results = (root / "results.txt").read_text()
    credentials_txt = (root / "credentials.txt").read_text()
    credentials_json = (root / "credentials.json").read_text()
    html = (tmp_path / "report.html").read_text()

    for surface in (console, results, credentials_txt, credentials_json, html):
        assert TARGET_SECRET in surface
        assert SCANNER_SECRET not in surface
    assert "Recovered credentials" in results and "Credentials saved to:" in results
    entries = json.loads(credentials_json)
    assert [entry["value"] for entry in entries] == [TARGET_SECRET]
    assert entries[0]["account"] == r"SCCMLAB\svc-naa"
    assert entries[0]["source"] == "PXEThief"


def test_non_secret_material_never_becomes_a_credential_artifact(monkeypatch, tmp_path):
    _harness(monkeypatch, tmp_path, pxe_recovered=[
        {"name": "media", "media_file": r"\SMS\variables.dat"},
        {"name": "bcd", "bcd_file": r"\SMS\boot.bcd"}])

    assert cli.main() == 0
    root = tmp_path / "sccm.lab"
    assert json.loads((root / "credentials.json").read_text()) == []
    assert (root / "credentials.txt").read_text() == ""
    assert "variables.dat" not in (root / "results.txt").read_text()
