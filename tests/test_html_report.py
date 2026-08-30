import subprocess
import sys

from ad_enum.reporting.html import render_html, write_html_report
from ad_enum.sccm_models import SCCMArtifactLimits, bounded_artifact_candidates, normalize_pxe_evidence


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


def test_sccm_artifact_policy_is_bounded():
    limits = SCCMArtifactLimits(max_files=2, max_file_bytes=10, max_total_bytes=15)
    selected = bounded_artifact_candidates([{"name": "a", "size": 10}, {"name": "b", "size": 6}, {"name": "c", "size": 1}], limits)
    assert [x["name"] for x in selected] == ["a", "c"]


def test_pxe_model_preserves_unknown_safe_defaults():
    result = normalize_pxe_evidence({"state": "not tested", "host": "MECM.sccm.lab", "sources": ["fixture"]})
    assert result["state"] == "NOT TESTED"
    assert result["implementation"] == "UNKNOWN"
    assert result["protection"] == "UNKNOWN"


def test_html_out_is_real_cli_flag():
    result = subprocess.run([sys.executable, "ad-enum.py", "--help"], capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "--html-out FILE" in result.stdout
