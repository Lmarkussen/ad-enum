"""Focused tests for the SCCMHunter discovery/profiling integration."""
import json
import sqlite3
import subprocess
from pathlib import Path

from ad_enum import sccmhunter_adapter as sh
from ad_enum.sccm import merge_sccmhunter


def _build_find_db(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE CAS(SiteCode)")
    connection.execute("CREATE TABLE ManagementPoints(Hostname, SiteCode, SigningStatus)")
    connection.execute("CREATE TABLE PXEDistributionPoints(Hostname, SigningStatus, SCCM, WDS)")
    connection.execute("CREATE TABLE SiteServers(Hostname, SiteCode, CAS, SigningStatus, "
                       "SiteServer, SMSProvider, Config, MSSQL)")
    connection.execute("INSERT INTO CAS VALUES ('P01')")
    connection.execute("INSERT INTO ManagementPoints VALUES ('MECM.sccm.lab', 'P01', '')")
    connection.execute("INSERT INTO ManagementPoints VALUES ('MECM.sccm.lab', 'P01', '')")
    connection.execute("INSERT INTO PXEDistributionPoints VALUES ('DP01.sccm.lab', '', '', '')")
    connection.execute("INSERT INTO SiteServers VALUES ('MECM.sccm.lab', 'P01', 'P01', '', 'True', '', '', '')")
    connection.commit()
    connection.close()


def test_parse_find_database_normalizes_roles_and_deduplicates(tmp_path):
    db = tmp_path / "find.db"
    _build_find_db(db)

    result = sh.parse_find_database(db)

    assert result["status"] == "PASS"
    assert result["site_codes"] == ["P01"]
    assert result["management_points"] == [{"host": "mecm.sccm.lab", "site_code": "P01"}]
    assert result["distribution_points"] == [{"host": "dp01.sccm.lab", "pxe": True}]
    assert result["site_servers"] == [{"host": "mecm.sccm.lab", "site_code": "P01"}]


def test_parse_find_database_reports_missing_database(tmp_path):
    result = sh.parse_find_database(tmp_path / "absent.db")
    assert result["status"] == "NOT TESTED" and result["errors"]
    assert result["management_points"] == [] and result["distribution_points"] == []


def _fake_checkout(tmp_path, monkeypatch, script_body):
    root = tmp_path / "SCCMHunter"
    (root / ".venv" / "bin").mkdir(parents=True)
    interpreter = root / ".venv" / "bin" / "python3"
    interpreter.write_text("#!/bin/sh\nexec python3 \"$@\"\n")
    interpreter.chmod(0o755)
    (root / "sccmhunter.py").write_text(script_body)
    monkeypatch.setenv("SCCMHUNTER_ROOT", str(root))
    return root


_WRITES_DB = """
import os, sqlite3, sys
home = os.environ["HOME"]
db = os.path.join(home, ".sccmhunter", "logs", "db")
os.makedirs(db, exist_ok=True)
connection = sqlite3.connect(os.path.join(db, "find.db"))
connection.execute("CREATE TABLE CAS(SiteCode)")
connection.execute("CREATE TABLE ManagementPoints(Hostname, SiteCode, SigningStatus)")
connection.execute("CREATE TABLE PXEDistributionPoints(Hostname, SigningStatus, SCCM, WDS)")
connection.execute("CREATE TABLE SiteServers(Hostname, SiteCode, CAS, SigningStatus, SiteServer, SMSProvider, Config, MSSQL)")
connection.execute("INSERT INTO CAS VALUES ('P01')")
connection.execute("INSERT INTO ManagementPoints VALUES ('MECM.sccm.lab', 'P01', '')")
connection.execute("INSERT INTO PXEDistributionPoints VALUES ('DP02.sccm.lab', '', '', '')")
connection.commit()
print("bind ok with password " + sys.argv[-1])
"""


def test_run_sccmhunter_isolates_home_and_never_persists_the_password(tmp_path, monkeypatch):
    _fake_checkout(tmp_path, monkeypatch, _WRITES_DB)
    workdir = tmp_path / "work"
    result = sh.run_sccmhunter("sccm.lab", "192.0.2.40", "localuser", "LabOnlySecret",
                               timeout=60, workdir=workdir)

    assert result["status"] == "PASS" and result["source"] == "SCCMHunter"
    assert result["management_points"] == [{"host": "mecm.sccm.lab", "site_code": "P01"}]
    assert result["distribution_points"] == [{"host": "dp02.sccm.lab", "pxe": True}]
    assert (workdir / ".sccmhunter" / "logs" / "db" / "find.db").is_file()
    stdout = (workdir / "stdout.txt").read_text()
    stderr = (workdir / "stderr.txt").read_text()
    assert "LabOnlySecret" not in stdout and "<redacted>" in stdout
    assert "LabOnlySecret" not in stderr
    assert "LabOnlySecret" not in result["command"] and "<password>" in result["command"]
    assert "LabOnlySecret" not in json.dumps(result)


def test_run_sccmhunter_reports_unavailable_tool_without_fabricating_state(tmp_path, monkeypatch):
    monkeypatch.setenv("SCCMHUNTER_ROOT", str(tmp_path / "missing"))
    result = sh.run_sccmhunter("sccm.lab", "192.0.2.40", "localuser", "LabOnlySecret",
                               timeout=5, workdir=tmp_path / "work")
    assert result["status"] == "NOT TESTED" and result["source"] == ""
    assert result["management_points"] == []


def test_capability_reports_missing_and_healthy_checkout(tmp_path, monkeypatch):
    monkeypatch.setenv("SCCMHUNTER_ROOT", str(tmp_path / "missing"))
    assert sh.sccmhunter_capability()["status"] == "NOT AVAILABLE"

    root = _fake_checkout(tmp_path, monkeypatch, "print('help')\n")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True, capture_output=True)
    assert sh.sccmhunter_capability()["status"] == "PASS"


def _native_result():
    return {
        "hosts": [], "site_code": "P01", "site_code_sources": [],
        "publication": {"objects": [{"dn": "CN=SMS-Site-P01"}]},
        "management_points": [{"host": "MECM.sccm.lab", "fqdn": "MECM.sccm.lab",
                               "ip_addresses": ["192.0.2.41"], "site_code": "P01",
                               "sources": ["SCCM LDAP publication"]}],
        "distribution_points": [], "site_servers": [], "sms_providers": [],
        "sql_servers": [], "sup_wsus": [],
        "pxe": {"status": "UNKNOWN", "implementation": "unknown", "sources": [], "evidence": []},
    }


def test_merge_corroborates_native_hosts_and_adds_new_pxe_endpoints():
    native = _native_result()
    hunter = {"status": "PASS", "site_codes": ["P01"],
              "management_points": [{"host": "mecm.sccm.lab", "site_code": "P01"}],
              "distribution_points": [{"host": "dp02.sccm.lab", "pxe": True}],
              "site_servers": [{"host": "mecm.sccm.lab", "site_code": "P01"}]}

    merged = merge_sccmhunter(native, hunter)

    mp = merged["management_points"][0]
    assert mp["host"] == "MECM.sccm.lab"
    assert mp["sources"] == ["SCCM LDAP publication", "SCCMHunter"]
    assert len(merged["management_points"]) == 1  # duplicate identity not repeated
    assert merged["distribution_points"] == [
        {"host": "dp02.sccm.lab", "fqdn": "dp02.sccm.lab", "ip_addresses": [], "site_code": "P01",
         "confidence": "sccmhunter", "sources": ["SCCMHunter"], "evidence": "SCCMHunter find",
         "pxe": "ENABLED"}]
    assert merged["pxe"]["status"] == "ENABLED"
    assert any("SCCMHunter" in (item.get("sources") or []) for item in merged["site_servers"])


def test_merge_preserves_native_pxe_evidence_when_sources_agree():
    native = _native_result()
    native["pxe"] = {"status": "ENABLED", "implementation": "unknown",
                     "sources": ["SCCM LDAP publication"],
                     "evidence": [{"dn": "CN=SMS-MP-P01", "attributes": ["netbootSCP"]}]}
    hunter = {"status": "PASS", "site_codes": [], "management_points": [],
              "distribution_points": [{"host": "dp02.sccm.lab", "pxe": True}], "site_servers": []}

    merged = merge_sccmhunter(native, hunter)

    assert {"dn": "CN=SMS-MP-P01", "attributes": ["netbootSCP"]} in merged["pxe"]["evidence"]
    assert {"source": "SCCMHunter", "attribute": "netbootServer",
            "hosts": ["dp02.sccm.lab"]} in merged["pxe"]["evidence"]
    assert set(merged["pxe"]["sources"]) == {"SCCM LDAP publication", "SCCMHunter"}


def test_merge_is_a_noop_when_sccmhunter_did_not_run():
    native = _native_result()
    snapshot = json.dumps(native, sort_keys=True)
    assert merge_sccmhunter(native, {"status": "NOT TESTED", "errors": ["unavailable"]}) == native
    assert json.dumps(native, sort_keys=True) == snapshot


def test_installer_provisions_isolated_sccmhunter_from_public_source():
    installer = Path(__file__).resolve().parents[1].joinpath("install.sh").read_text(encoding="utf-8")
    assert "https://github.com/garrettfoster13/sccmhunter.git" in installer
    assert '.cache/SCCMHunter' in installer
    assert 'sccmhunter_root/.venv' in installer
    assert "sccmhunter.py --help" in installer
