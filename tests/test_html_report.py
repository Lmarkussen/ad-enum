import subprocess
import sys

from ad_enum.reporting.html import render_html, write_html_report
from ad_enum.sccm_models import (SCCMArtifactLimits, bounded_artifact_candidates,
                                  normalize_mp_metadata, normalize_pxe_evidence,
                                  normalize_dp_content, normalize_task_sequences,
                                  normalize_sccm_topology, normalize_sccm_capabilities,
                                  normalize_cred1_evidence, sccm_technique_coverage)


def _model():
    return {
        "domain": "sccm.lab", "target": "dc.sccm.lab", "workspace": "sccm.lab/",
        "banner": "AD-Enum\n@Evilhaxxor", "category_order": ["GPO", "SMB"],
        "collectors": {"Native LDAP": "PASS", "NetExec": "PARTIAL"},
        "inventory": {"Users": 3, "Computers": 4},
        "findings": [{"category": "GPO", "title": "Credential exposure", "status": "confirmed",
                      "affected_object": "OU=<script>", "evidence": {"impact": "use & review", "value": "TargetSecret!"},
                      "sources": [{"source": "SYSVOL"}]}],
        "credentials": [{"account": "fixture", "type": "password", "value": "TargetSecret!",
                         "source": "startup.ps1", "context": "GPO"}],
        "sccm": {"site_code": "P01"},
        "coverage": {"SCCM / PXE": {"status": "NOT TESTED", "detail": "offline"}},
    }


def test_html_is_standalone_escaped_and_contains_core_sections(tmp_path):
    report = render_html(_model())
    assert report.startswith("<!doctype html>")
    assert "<script>alert(1)</script>" not in report
    assert "&lt;script&gt;" in report
    assert "TargetSecret!" in report
    assert "Credentials / Secrets" in report
    assert "SCCM / MECM" in report
    assert "prefers-color-scheme" in report
    assert "https://" not in report
    destination = tmp_path / "nested" / "report.html"
    assert write_html_report(destination, _model()) == destination
    assert destination.is_file()


def test_html_shows_smb_share_access():
    model = _model()
    model["smb_shares"] = [{"host": "FILE01", "share": "Deploy$", "unc": "\\\\FILE01\\Deploy$",
                            "readable": True, "writable": True}]
    report = render_html(model)
    assert "SMB Share Access" in report
    assert "READ / WRITE" in report
    assert "FILE01" in report


def test_html_lists_aggregated_affected_objects():
    model = _model()
    model["findings"] = [{"category": "SMB", "title": "SMB signing not required — 2 host(s)",
                           "status": "single-source", "evidence": {
                               "hosts": [{"fqdn": "MECM.sccm.lab"}, {"fqdn": "CLIENT.sccm.lab"}]}}]
    report = render_html(model)
    assert "Affected objects (2)" in report
    assert "MECM.sccm.lab" in report
    assert "CLIENT.sccm.lab" in report


def test_html_shows_authenticated_access():
    model = _model()
    model["access"] = [{"host": "DC.sccm.lab", "roles": ["Domain Controller"],
                         "protocol": "SSH", "authentication": "AUTHENTICATED",
                         "privilege": "UNKNOWN", "principal": "user", "source": "NetExec"}]
    report = render_html(model)
    assert "Authenticated Access" in report
    assert "AUTHENTICATED" in report


def test_html_shows_cred1_finding_credential_details():
    model = _model()
    model["findings"] = [{"category": "SCCM", "rule": "CRED-1",
                           "title": "CRED-1 — PXE boot media exposes credential material",
                           "status": "confirmed", "affected_object": "10.0.0.41",
                           "evidence": {"dp": "10.0.0.41", "site": "P01", "policies": 5,
                                        "unique_secrets": 1, "type": "task_sequence_variable",
                                        "name": "SyntheticName", "value": "ADEnum-CRED1-Test-Secret",
                                        "source_policy": "Policy-A"}}]
    report = render_html(model)
    assert "SyntheticName" in report
    assert "ADEnum-CRED1-Test-Secret" in report
    assert "Policy-A" in report


def test_installer_uses_explicit_netexec_package_path():
    installer = open("install.sh", encoding="utf-8").read()
    assert "pipx install --force netexec" in installer


def test_cred1_model_is_safe_and_never_implies_decryption():
    result = normalize_cred1_evidence({"dp": "MECM", "BootFileName": "pxeboot.n12",
                                       "media_protection": "protected", "artifacts": [".boot.bcd"]})
    assert result["boot_file"] == "pxeboot.n12"
    assert result["media_protection"] == "PROTECTED"
    assert result["secret_inspection"] == "NOT ATTEMPTED"
    assert sccm_technique_coverage()["CRED-1"] == "PARTIAL"


def test_sccm_artifact_policy_is_bounded():
    limits = SCCMArtifactLimits(max_files=2, max_file_bytes=10, max_total_bytes=15)
    selected = bounded_artifact_candidates([{"name": "a", "size": 10}, {"name": "b", "size": 6}, {"name": "c", "size": 1}], limits)
    assert [x["name"] for x in selected] == ["a", "c"]


def test_pxe_model_preserves_unknown_safe_defaults():
    result = normalize_pxe_evidence({"state": "not tested", "host": "MECM.sccm.lab", "sources": ["fixture"]})
    assert result["state"] == "NOT TESTED"
    assert result["implementation"] == "UNKNOWN"
    assert result["protection"] == "UNKNOWN"


def test_sccm_offline_models_preserve_evidence_and_explicit_states():
    mp = normalize_mp_metadata({"fqdn": "MECM.sccm.lab", "sitecode": "P01",
                                "protocol": "http", "version": "2403",
                                "sources": ["MPLIST"]})
    assert mp["site_code"] == "P01"
    assert mp["protocol"] == "HTTP"
    assert mp["sources"] == ["MPLIST"]

    content = normalize_dp_content([
        {"package_id": "P010001", "content_id": "C010001", "name": "Boot image",
         "size": 4, "url": "http://mecm/sms_dp_smspkg$/P010001"},
    ])
    assert content[0]["content_id"] == "C010001"
    assert content[0]["access"] == "UNKNOWN"

    sequences = normalize_task_sequences([{"id": "TS100", "name": "WinPE",
                                           "package_references": ["P010001"],
                                           "access": "denied"}])
    assert sequences[0]["id"] == "TS100"
    assert sequences[0]["access"] == "DENIED"

    topology = normalize_sccm_topology({"site_code": "P01", "nodes": [
        {"host": "MECM.sccm.lab", "role": "DP", "status": "partial",
         "low_priv_visibility": "not observable", "sources": ["fixture"]}],
        "relationships": [{"from": "P01", "to": "MECM.sccm.lab", "role": "DP",
                            "confidence": "candidate"}]})
    assert topology["nodes"][0]["status"] == "PARTIAL"
    assert topology["nodes"][0]["low_priv_visibility"] == "NOT OBSERVABLE"
    assert topology["relationships"][0]["confidence"] == "CANDIDATE"

    coverage = normalize_sccm_capabilities({"DP": {"status": "not tested", "detail": "offline"},
                                             "PXE": "complete"})
    assert coverage["DP"]["status"] == "NOT TESTED"
    assert coverage["PXE"]["status"] == "COMPLETE"


def test_html_out_is_real_cli_flag():
    result = subprocess.run([sys.executable, "ad-enum.py", "--help"], capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "--html-out FILE" in result.stdout
