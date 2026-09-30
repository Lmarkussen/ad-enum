"""Multi-endpoint SCCM/PXE validation regression tests.

These prove that every unique discovered endpoint is validated independently
and that a vulnerable (or failing) endpoint never stops the remaining ones.
"""
import json
import sys
from pathlib import Path

from ad_enum import cli
from ad_enum.sccm import pxe_candidates
from ad_enum.sccm_models import normalize_pxe_validation
from test_pipeline_smoke import FakeCollector


def _sccm(entries, *, management_points=()):
    return {"hosts": [], "management_points": list(management_points),
            "distribution_points": list(entries), "site_servers": [],
            "sms_providers": [], "sql_servers": [], "sup_wsus": [],
            "pxe": {"status": "UNKNOWN"}, "status": "sccm-publication-and-inventory"}


def _configure(monkeypatch, tmp_path, sccm_result, states, calls, *,
               raises=(), dns_map=None, hunter=None):
    monkeypatch.setattr(cli, "Collector", FakeCollector)
    monkeypatch.setattr(cli, "probe_anonymous_ldap",
                        lambda *a, **k: {"bind": "DENIED", "rootdse": "DENIED",
                                         "domain_data": "DENIED", "sources": ["test"]})
    monkeypatch.setattr(cli, "probe_anonymous_smb",
                        lambda *a, **k: {"session": "DENIED", "share_enumeration": "DENIED",
                                         "shares": [], "sources": ["test"]})
    monkeypatch.setattr(cli, "collect_sysvol", lambda *a, **k: {"status": "PASS", "files": []})
    monkeypatch.setattr(cli, "collect_netlogon", lambda *a, **k: {"status": "PASS", "files": []})
    monkeypatch.setattr(cli, "discover_sccm", lambda *a, **k: sccm_result)
    monkeypatch.setattr(cli, "probe_management_points", lambda *a, **k: [])
    monkeypatch.setattr(cli, "execute_external", lambda *a, **k: ({}, []))
    monkeypatch.setattr(cli, "pxethief_capability",
                        lambda: {"status": "PASS", "detail": "fixture"})
    monkeypatch.setattr(cli, "run_sccmhunter", lambda *a, **k: hunter or {
        "status": "NOT TESTED", "source": "", "command": "", "commit": "",
        "errors": ["fixture"], "site_codes": [], "management_points": [],
        "distribution_points": [], "site_servers": []})
    monkeypatch.setattr(cli, "sccmhunter_capability", lambda *a, **k: {
        "status": "NOT AVAILABLE", "detail": "fixture", "root": "", "commit": ""})
    if dns_map is not None:
        monkeypatch.setattr(cli, "build_dns_map", lambda *a, **k: dns_map)
        monkeypatch.setattr(cli, "dns_map_text", lambda *a, **k: "")

    def fake_run(target, *, timeout, workdir, root=None):
        workdir = Path(workdir)
        calls.append({"target": target, "workdir": workdir})
        workdir.mkdir(parents=True, exist_ok=True)
        (workdir / "run.json").write_text(json.dumps({"dp": target}), encoding="utf-8")
        if target in raises:
            raise RuntimeError("fixture endpoint failure")
        state = states.get(target, "NOT TESTED")
        return normalize_pxe_validation({
            "dp": target, "state": state, "source": "PXEThief",
            "recovered_count": 3 if state == "VULNERABLE" else 0,
            "errors": [] if state in {"VULNERABLE", "NOT VULNERABLE"} else ["no PXE response"]})

    monkeypatch.setattr(cli, "run_pxethief", fake_run)
    monkeypatch.setattr(sys, "argv", ["ad-enum.py", "-u", "fixture", "-p", "not-a-real-secret",
                                      "-domain", "sccm.lab", "-dc-ip", "192.0.2.10",
                                      "--modules", "adcs", "--output-dir", str(tmp_path),
                                      "--no-color"])


def _endpoints(prefix="dp", addresses=("192.0.2.11", "192.0.2.12", "192.0.2.13")):
    return [{"fqdn": f"{prefix}{index}.example.local", "ip_addresses": [address],
             "site_code": "P01"} for index, address in enumerate(addresses, start=1)]


def test_every_unique_endpoint_is_validated_even_when_the_first_is_vulnerable(monkeypatch, tmp_path):
    states = {"192.0.2.11": "VULNERABLE", "192.0.2.12": "NOT VULNERABLE", "192.0.2.13": "NOT TESTED"}
    calls = []
    _configure(monkeypatch, tmp_path, _sccm(_endpoints()), states, calls)

    assert cli.main() == 0
    assert [call["target"] for call in calls] == ["192.0.2.11", "192.0.2.12", "192.0.2.13"]

    rows = json.loads((tmp_path / "sccm.lab" / "SCCM" / "pxe-validation.json").read_text())
    assert [row["dp"] for row in rows] == ["192.0.2.11", "192.0.2.12", "192.0.2.13"]
    assert [row["state"] for row in rows] == ["VULNERABLE", "NOT VULNERABLE", "NOT TESTED"]

    workdirs = [call["workdir"] for call in calls]
    assert len(set(workdirs)) == 3
    assert all("pxethief" in workdir.parts and "raw" in workdir.parts for workdir in workdirs)
    assert all((workdir / "run.json").is_file() for workdir in workdirs)


def test_endpoint_execution_error_does_not_stop_later_endpoints(monkeypatch, tmp_path):
    states = {"192.0.2.12": "VULNERABLE"}
    calls = []
    _configure(monkeypatch, tmp_path, _sccm(_endpoints()), states, calls,
               raises={"192.0.2.11"})

    assert cli.main() == 0
    assert [call["target"] for call in calls] == ["192.0.2.11", "192.0.2.12", "192.0.2.13"]

    rows = json.loads((tmp_path / "sccm.lab" / "SCCM" / "pxe-validation.json").read_text())
    assert [row["state"] for row in rows] == ["NOT TESTED", "VULNERABLE", "NOT TESTED"]
    assert "fixture endpoint failure" in rows[0]["errors"][0]


def test_duplicate_hostname_and_ip_identity_is_validated_once(monkeypatch, tmp_path):
    entries = [
        {"fqdn": "mecm.example.local", "ip_addresses": ["192.0.2.10"], "site_code": "P01"},
        {"fqdn": "MECM.EXAMPLE.LOCAL", "ip_addresses": [], "site_code": "P01"},
        {"fqdn": "dp02.example.local", "ip_addresses": ["192.0.2.12"], "site_code": "P01"},
    ]
    dns_map = {"records": [{"fqdn": "mecm.example.local", "ip_addresses": ["192.0.2.10"]}]}
    calls = []
    _configure(monkeypatch, tmp_path, _sccm(entries), {"192.0.2.10": "NOT VULNERABLE"},
               calls, dns_map=dns_map)

    assert cli.main() == 0
    assert [call["target"] for call in calls] == ["192.0.2.10", "192.0.2.12"]


def test_pxe_candidates_deduplicates_hostname_and_ip_identity():
    result = {"distribution_points": [{"fqdn": "mecm.example.local", "ip_addresses": ["192.0.2.10"]}],
              "management_points": [{"fqdn": "mecm.example.local", "ip_addresses": []},
                                    {"fqdn": "mecm.example.local", "ip_addresses": ["192.0.2.10"]}]}
    dns_map = {"records": [{"fqdn": "mecm.example.local", "ip_addresses": ["192.0.2.10"]}]}

    assert pxe_candidates(result, dns_map) == [
        {"dp": "192.0.2.10", "host": "mecm.example.local", "site_code": "",
         "basis": "distribution-point", "pxe_evidence": False}]


def test_pxe_candidates_keeps_genuinely_distinct_endpoints():
    result = {"distribution_points": [{"fqdn": "dp01.example.local", "ip_addresses": ["192.0.2.11"]},
                                      {"fqdn": "dp02.example.local", "ip_addresses": ["192.0.2.12"]}]}
    dns_map = {"records": [{"fqdn": "dp01.example.local", "ip_addresses": ["192.0.2.11"]},
                           {"fqdn": "dp02.example.local", "ip_addresses": ["192.0.2.12"]}]}

    assert [c["dp"] for c in pxe_candidates(result, dns_map)] == ["192.0.2.11", "192.0.2.12"]


def test_multi_endpoint_results_txt_is_tidy_and_ansi_free(monkeypatch, tmp_path):
    states = {"192.0.2.11": "NOT VULNERABLE", "192.0.2.12": "VULNERABLE", "192.0.2.13": "NOT TESTED"}
    calls = []
    _configure(monkeypatch, tmp_path, _sccm(_endpoints()), states, calls)

    assert cli.main() == 0
    report = (tmp_path / "sccm.lab" / "results.txt").read_text()
    section = report.split("------------[ SCCM ]------------\n", 1)[1].split("Workspace", 1)[0]

    assert "PXE — 192.0.2.11" in section and "State   NOT VULNERABLE" in section
    assert "PXE VULNERABLE — 192.0.2.12" in section and "Recovered  3" in section
    assert "PXE — 192.0.2.13" in section and "State   NOT TESTED" in section
    for marker in ("[+]", "[-]", "[!]", "Blank password", "variables.dat", "Decrypting using"):
        assert marker not in section
    assert "\033[" not in report


def _hunter_result(*hosts):
    return {"status": "PASS", "source": "SCCMHunter", "command": "py sccmhunter.py find",
            "commit": "fixture", "site_codes": ["P01"], "management_points": [],
            "distribution_points": [{"host": host, "pxe": True} for host in hosts],
            "site_servers": []}


def test_sccmhunter_discovered_endpoint_joins_the_pxethief_candidate_set(monkeypatch, tmp_path):
    calls = []
    _configure(monkeypatch, tmp_path, _sccm(_endpoints(addresses=("192.0.2.11",))),
               {"192.0.2.11": "VULNERABLE", "dp02.example.local": "NOT VULNERABLE"},
               calls, hunter=_hunter_result("dp02.example.local"))

    assert cli.main() == 0
    assert [call["target"] for call in calls] == ["192.0.2.11", "dp02.example.local"]

    rows = json.loads((tmp_path / "sccm.lab" / "SCCM" / "pxe-validation.json").read_text())
    assert [row["state"] for row in rows] == ["VULNERABLE", "NOT VULNERABLE"]

    inventory = json.loads((tmp_path / "sccm.lab" / "SCCM" / "inventory.json").read_text())
    hosts = [entry.get("host") or entry.get("fqdn") for entry in inventory["distribution_points"]]
    assert hosts == ["dp1.example.local", "dp02.example.local"]


def test_sccm_infrastructure_summary_is_compact_and_hunter_free_of_raw_output(monkeypatch, tmp_path):
    calls = []
    _configure(monkeypatch, tmp_path, _sccm(_endpoints(addresses=("192.0.2.11",))),
               {"192.0.2.11": "NOT VULNERABLE", "dp02.example.local": "NOT VULNERABLE"},
               calls, hunter=_hunter_result("dp02.example.local"))

    assert cli.main() == 0
    report = (tmp_path / "sccm.lab" / "results.txt").read_text()
    block = report.split("SCCM Infrastructure\n", 1)[1].split("\n\n", 1)[0]

    assert "Site" in block and "P01" in block
    assert "Distribution Point" in block
    assert "dp02.example.local" in block and "PXE ENABLED" in block
    assert "SCCMHunter" in block
    for marker in ("[+]", "[-]", "[!]", "First time use detected"):
        assert marker not in report
    assert "\033[" not in report
