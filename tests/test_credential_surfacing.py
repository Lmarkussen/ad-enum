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
    assert "Network Access Account" in section
    assert r"SCCMLAB\svc-osd" in section
    assert TARGET_SECRET in section
    assert "Credentials saved to:" in section
    assert "sccm.lab/credentials.txt" in section


def test_local_admin_password_renders_with_default_account(tmp_path):
    section = _render([_pxe_finding([{"name": "OSDLocalAdminPassword",
                                      "value": TARGET_SECRET}])], tmp_path)

    assert "Local Administrator Password" in section
    assert "Administrator" in section
    assert "Password" in section and TARGET_SECRET in section


def test_join_account_without_password_is_account_information(tmp_path):
    section = _render([_pxe_finding([{"name": "OSDJoinAccount", "value": r"sccm.lab\svc-join"}])],
                      tmp_path)

    assert "Account information" in section
    assert "Domain Join Account" in section and r"sccm.lab\svc-join" in section
    assert "Password" not in section
    assert "Recovered credentials" not in section


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
    # Related variables are correlated into operator-friendly credentials, and
    # registered user is metadata rather than a credential.
    assert "Network Access Account" in section
    assert "Local Administrator Password" in section
    assert "Domain Join Credential" in section
    assert r"sccm.lab\svc-join" in section
    assert "Deployment metadata" in section and "Registered User" in section


def _sccm(entries):
    return {"hosts": [], "management_points": [], "distribution_points": list(entries),
            "site_servers": [], "sms_providers": [], "sql_servers": [], "sup_wsus": [],
            "pxe": {"status": "ENABLED"}, "status": "sccm-publication-and-inventory"}


def _harness(monkeypatch, tmp_path, *, pxe_recovered, dp_credentials=()):
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
        "downloaded": 0, "interesting": len(dp_credentials),
        "files": [], "credentials": list(dp_credentials),
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


def test_domain_join_pair_renders_as_one_credential(tmp_path):
    section = _render([_pxe_finding([
        {"name": "OSDJoinAccount", "value": r"sccm.lab\sccm-naa",
         "step": "Apply Network Settings"},
        {"name": "OSDJoinPassword", "value": "TargetJoinPassword",
         "step": "Apply Network Settings"}])], tmp_path)

    assert section.count("Domain Join Credential") == 1
    assert r"sccm.lab\sccm-naa" in section
    assert "TargetJoinPassword" in section
    assert "Apply Network Settings" in section


def test_two_steps_do_not_cross_pair_credentials(tmp_path):
    section = _render([_pxe_finding([
        {"name": "OSDJoinAccount", "value": "ACCT-A", "step": "Step A"},
        {"name": "OSDJoinAccount", "value": "ACCT-B", "step": "Step B"},
        {"name": "OSDJoinPassword", "value": "PASS-B", "step": "Step B"}])], tmp_path)

    # Only the account whose step also carries a password becomes a credential;
    # the orphaned account from a different step is never cross-paired.
    assert "ACCT-B" in section and "PASS-B" in section
    assert "ACCT-A" in section
    credentials_block = section.split("Recovered credentials", 1)[1].split(
        "Account information", 1)[0]
    assert "ACCT-A" not in credentials_block


def test_join_password_without_account_keeps_secret_visible(tmp_path):
    section = _render([_pxe_finding([
        {"name": "OSDJoinPassword", "value": "TargetJoinPassword",
         "step": "Apply Network Settings"}])], tmp_path)

    assert "Domain Join Credential" in section
    assert "TargetJoinPassword" in section
    assert "Password  " in section
    # No account was recovered, so none is fabricated.
    assert "Account  " not in section


def test_registered_user_is_deployment_metadata_not_a_credential(monkeypatch, tmp_path):
    _harness(monkeypatch, tmp_path, pxe_recovered=[
        {"name": "OSDRegisteredUserName", "value": "User",
         "step": "Apply Windows Settings"}])

    assert cli.main() == 0
    root = tmp_path / "sccm.lab"
    results = (root / "results.txt").read_text()
    assert "Deployment metadata" in results and "Registered User" in results
    assert "Recovered credentials" not in results
    assert json.loads((root / "credentials.json").read_text()) == []


LAB_SHAPED_RECOVERY = [
    {"name": "NetworkAccessAccount", "username": r"SCCMLAB\naa-lab",
     "value": "TargetNaaPassword"},
    {"name": "OSDRegisteredUserName", "value": "User",
     "step": "Apply Windows Settings"},
    {"name": "OSDLocalAdminPassword", "value": "TargetLocalAdminPassword",
     "step": "Apply Windows Settings"},
    {"name": "OSDJoinAccount", "value": r"sccm.lab\sccm-naa",
     "step": "Apply Network Settings"},
    {"name": "OSDJoinPassword", "value": "TargetJoinPassword",
     "step": "Apply Network Settings"},
]


def test_osd_credentials_flow_to_artifacts_with_improved_metadata(monkeypatch, tmp_path):
    _harness(monkeypatch, tmp_path, pxe_recovered=LAB_SHAPED_RECOVERY)

    assert cli.main() == 0
    root = tmp_path / "sccm.lab"
    entries = json.loads((root / "credentials.json").read_text())
    by_value = {entry["value"]: entry for entry in entries}

    assert set(by_value) == {"TargetNaaPassword", "TargetLocalAdminPassword",
                             "TargetJoinPassword"}
    join = by_value["TargetJoinPassword"]
    assert join["account"] == r"sccm.lab\sccm-naa"  # real account, never UNKNOWN
    assert join["type"] == "Domain Join Password"
    assert join["context"] == "Apply Network Settings"
    assert join["variables"] == ["OSDJoinAccount", "OSDJoinPassword"]
    local_admin = by_value["TargetLocalAdminPassword"]
    assert local_admin["account"] == "Administrator"
    assert local_admin["type"] == "Local Administrator Password"
    naa = by_value["TargetNaaPassword"]
    assert naa["account"] == r"SCCMLAB\naa-lab"

    credentials_txt = (root / "credentials.txt").read_text()
    for expected in ("Domain Join Password", "Local Administrator Password",
                     "Network Access Account", r"sccm.lab\sccm-naa"):
        assert expected in credentials_txt
    # Registered user is metadata, never consolidated as a credential.
    assert all(entry["value"] != "User" for entry in entries)


def test_osd_scanner_secret_absent_everywhere_and_target_secrets_present(
        monkeypatch, tmp_path, capsys):
    _harness(monkeypatch, tmp_path, pxe_recovered=LAB_SHAPED_RECOVERY)

    assert cli.main() == 0
    console = capsys.readouterr().out
    root = tmp_path / "sccm.lab"
    surfaces = {
        "console": console,
        "results.txt": (root / "results.txt").read_text(),
        "credentials.txt": (root / "credentials.txt").read_text(),
        "credentials.json": (root / "credentials.json").read_text(),
        "report.html": (tmp_path / "report.html").read_text(),
    }
    for name, surface in surfaces.items():
        assert SCANNER_SECRET not in surface, name
    for name in ("console", "results.txt", "credentials.txt", "credentials.json",
                 "report.html"):
        surface = surfaces[name]
        assert "TargetJoinPassword" in surface, name
        assert "TargetLocalAdminPassword" in surface, name


def test_domain_join_credential_dedupe_merges_across_sources(monkeypatch, tmp_path):
    _harness(
        monkeypatch, tmp_path,
        pxe_recovered=[
            {"name": "OSDJoinAccount", "value": r"sccm.lab\sccm-naa",
             "step": "Apply Network Settings"},
            {"name": "OSDJoinPassword", "value": "SharedJoinSecret",
             "step": "Apply Network Settings"}],
        dp_credentials=[
            {"type": "SCCM DP file password", "name": "password",
             "username": r"sccm.lab\sccm-naa", "value": "SharedJoinSecret",
             "path": "loot/packages/Join.ps1", "dp": "10.1.10.41"}])

    assert cli.main() == 0
    credentials = json.loads((tmp_path / "sccm.lab" / "credentials.json").read_text())
    matching = [entry for entry in credentials if entry["value"] == "SharedJoinSecret"]
    assert len(matching) == 1
    assert matching[0]["account"] == r"sccm.lab\sccm-naa"
    assert matching[0]["sources"] == ["PXEThief", "SCCMSecrets"]
    assert matching[0]["variables"] == ["OSDJoinAccount", "OSDJoinPassword"]
