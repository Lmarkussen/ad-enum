"""Multi-Distribution-Point SCCMSecrets inspection regression tests."""
import json
import sys
from pathlib import Path

from ad_enum import cli
from ad_enum.sccm_models import normalize_pxe_validation
from test_pipeline_smoke import FakeCollector


def _sccm(entries):
    return {"hosts": [], "management_points": [], "distribution_points": list(entries),
            "site_servers": [], "sms_providers": [], "sql_servers": [], "sup_wsus": [],
            "pxe": {"status": "ENABLED"}, "status": "sccm-publication-and-inventory"}


def _dps(addresses):
    return [{"fqdn": f"dp{index}.example.local", "ip_addresses": [address], "site_code": "P01"}
            for index, address in enumerate(addresses, start=1)]


def _configure(monkeypatch, tmp_path, entries, results, calls, *,
               raises=(), pxethief_recovered=()):
    monkeypatch.setattr(cli, "Collector", FakeCollector)
    monkeypatch.setattr(cli, "probe_anonymous_ldap",
                        lambda *a, **k: {"bind": "DENIED", "rootdse": "DENIED",
                                         "domain_data": "DENIED", "sources": ["test"]})
    monkeypatch.setattr(cli, "probe_anonymous_smb",
                        lambda *a, **k: {"session": "DENIED", "share_enumeration": "DENIED",
                                         "shares": [], "sources": ["test"]})
    monkeypatch.setattr(cli, "collect_sysvol", lambda *a, **k: {"status": "PASS", "files": []})
    monkeypatch.setattr(cli, "collect_netlogon", lambda *a, **k: {"status": "PASS", "files": []})
    monkeypatch.setattr(cli, "discover_sccm", lambda *a, **k: _sccm(entries))
    monkeypatch.setattr(cli, "probe_management_points", lambda *a, **k: [])
    monkeypatch.setattr(cli, "execute_external", lambda *a, **k: ({}, []))
    monkeypatch.setattr(cli, "pxethief_capability", lambda *a, **k: {"status": "PASS", "detail": "x"})
    monkeypatch.setattr(cli, "sccmhunter_capability", lambda *a, **k: {"status": "NOT AVAILABLE",
                                                                       "detail": "x", "root": "", "commit": ""})
    monkeypatch.setattr(cli, "run_sccmhunter", lambda *a, **k: {
        "status": "NOT TESTED", "source": "", "command": "", "commit": "", "errors": ["x"],
        "site_codes": [], "management_points": [], "distribution_points": [], "site_servers": []})
    monkeypatch.setattr(cli, "run_pxethief", lambda dp, *a, **k: normalize_pxe_validation({
        "dp": str(dp), "state": "VULNERABLE", "source": "PXEThief", "recovered": list(pxethief_recovered)}))
    monkeypatch.setattr(cli, "sccmsecrets_capability", lambda *a, **k: {"status": "PASS", "detail": "x"})

    def fake_files(dp, username, password, *, timeout=None, workdir=None, **kwargs):
        workdir = Path(workdir)
        calls.append({"dp": str(dp), "workdir": workdir})
        workdir.mkdir(parents=True, exist_ok=True)
        (workdir / "stdout.txt").write_text("fixture")
        if str(dp) in raises:
            raise RuntimeError("fixture DP failure")
        return dict(results.get(str(dp), {"state": "NOT TESTED", "access": "UNKNOWN", "indexed": 0,
                                          "downloaded": 0, "interesting": 0, "files": [],
                                          "credentials": [], "errors": ["x"], "source": "SCCMSecrets",
                                          "command": "fixture"}), dp=str(dp), source="SCCMSecrets")

    monkeypatch.setattr(cli, "run_sccmsecrets_files", fake_files)
    monkeypatch.setattr(sys, "argv", ["ad-enum.py", "-u", "fixture", "-p", "not-a-real-secret",
                                      "-domain", "sccm.lab", "-dc-ip", "192.0.2.10",
                                      "--modules", "adcs", "--output-dir", str(tmp_path), "--no-color"])


def _ok(indexed=10, interesting=0, credentials=()):
    return {"state": "ACCESSIBLE", "access": "AUTHENTICATED", "indexed": indexed,
            "downloaded": indexed, "interesting": interesting,
            "files": [], "credentials": list(credentials), "errors": [],
            "source": "SCCMSecrets", "command": "fixture"}


def _rows(tmp_path):
    return json.loads((tmp_path / "sccm.lab" / "SCCM" / "dp-content.json").read_text())


def test_every_unique_dp_is_inspected(monkeypatch, tmp_path):
    entries = _dps(("192.0.2.21", "192.0.2.22", "192.0.2.23"))
    calls = []
    _configure(monkeypatch, tmp_path, entries,
               {"192.0.2.21": _ok(5), "192.0.2.22": _ok(6), "192.0.2.23": _ok(7)}, calls)

    assert cli.main() == 0
    assert [call["dp"] for call in calls] == ["192.0.2.21", "192.0.2.22", "192.0.2.23"]
    assert [row["indexed"] for row in _rows(tmp_path)] == [5, 6, 7]
    workdirs = [call["workdir"] for call in calls]
    assert len(set(workdirs)) == 3
    assert all("sccmsecrets" in workdir.parts and "raw" in workdir.parts for workdir in workdirs)


def test_first_dp_credentials_do_not_stop_later_dps(monkeypatch, tmp_path):
    entries = _dps(("192.0.2.21", "192.0.2.22", "192.0.2.23"))
    calls = []
    creds = [{"type": "SCCM DP file password", "name": "password", "username": "svc-app",
              "value": "ExampleOnly-Secret", "path": "loot/packages/Join.ps1", "dp": "192.0.2.21"}]
    _configure(monkeypatch, tmp_path, entries,
               {"192.0.2.21": _ok(interesting=1, credentials=creds),
                "192.0.2.22": _ok(), "192.0.2.23": _ok()}, calls)

    assert cli.main() == 0
    assert [call["dp"] for call in calls] == ["192.0.2.21", "192.0.2.22", "192.0.2.23"]
    rows = _rows(tmp_path)
    assert rows[0]["credential_count"] == 1
    assert [row["state"] for row in rows] == ["ACCESSIBLE"] * 3


def test_first_dp_error_does_not_stop_later_dps(monkeypatch, tmp_path):
    entries = _dps(("192.0.2.21", "192.0.2.22"))
    calls = []
    _configure(monkeypatch, tmp_path, entries, {"192.0.2.22": _ok()}, calls,
               raises={"192.0.2.21"})

    assert cli.main() == 0
    assert [call["dp"] for call in calls] == ["192.0.2.21", "192.0.2.22"]
    rows = _rows(tmp_path)
    assert rows[0]["state"] == "NOT TESTED" and "fixture DP failure" in rows[0]["errors"][0]
    assert rows[1]["state"] == "ACCESSIBLE"


def test_duplicate_hostname_and_ip_identity_is_inspected_once(monkeypatch, tmp_path):
    entries = [{"fqdn": "dp1.example.local", "ip_addresses": ["192.0.2.21"], "site_code": "P01"},
               {"fqdn": "DP1.EXAMPLE.LOCAL", "ip_addresses": [], "site_code": "P01"},
               {"fqdn": "dp2.example.local", "ip_addresses": ["192.0.2.22"], "site_code": "P01"}]
    calls = []
    _configure(monkeypatch, tmp_path, entries, {"192.0.2.21": _ok(), "192.0.2.22": _ok()}, calls)

    assert cli.main() == 0
    assert [call["dp"] for call in calls] == ["192.0.2.21", "192.0.2.22"]


def test_dp_content_summary_is_tidy_and_ansi_free(monkeypatch, tmp_path):
    entries = _dps(("192.0.2.21", "192.0.2.22"))
    calls = []
    _configure(monkeypatch, tmp_path, entries,
               {"192.0.2.21": _ok(143, interesting=6), "192.0.2.22": _ok(2)}, calls)

    assert cli.main() == 0
    report = (tmp_path / "sccm.lab" / "results.txt").read_text()
    section = report.split("------------[ SCCM ]------------\n", 1)[1].split("Workspace", 1)[0]

    assert "DP CONTENT — 192.0.2.21" in section
    block = section.split("DP CONTENT — 192.0.2.21", 1)[1].split("\n\n", 1)[0]
    fields = {}
    for line in block.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            fields[parts[0]] = parts[1].strip()
    assert fields["Indexed"] == "143"
    assert fields["Interesting"] == "6"
    assert fields["Access"] == "AUTHENTICATED"
    assert fields["Source"] == "SCCMSecrets"
    for marker in ("#####", "Starting authenticated file download", "Handled package", "[+]", "\x1b["):
        assert marker not in report


def test_recovered_credential_dedupe_preserves_multiple_sources(monkeypatch, tmp_path):
    entries = _dps(("192.0.2.21",))
    calls = []
    shared = {"type": "SCCM DP file password", "name": "password", "username": "svc-naa",
              "value": "ExampleOnlySecret", "path": "loot/packages/Join.ps1", "dp": "192.0.2.21"}
    _configure(monkeypatch, tmp_path, entries, {"192.0.2.21": _ok(interesting=1, credentials=[shared])},
               calls,
               pxethief_recovered=[{"name": "NetworkAccessAccount", "username": "svc-naa",
                                    "value": "ExampleOnlySecret"}])

    assert cli.main() == 0
    credentials = json.loads((tmp_path / "sccm.lab" / "credentials.json").read_text())
    matching = [entry for entry in credentials if entry["value"] == "ExampleOnlySecret"]
    assert len(matching) == 1
    assert matching[0]["sources"] == ["PXEThief", "SCCMSecrets"]
    assert len(matching[0]["contexts"]) == 2
