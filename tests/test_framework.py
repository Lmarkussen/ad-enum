from ad_enum.adapters.certipy import CertipyAdapter
from ad_enum.core.coverage import CoverageReport, CoverageStatus
from ad_enum.core.corroboration import Corroboration, SourceAssessment
from ad_enum.adcs import scan
from ad_enum.fixtures import collect_fixture
import json
from pathlib import Path
from ad_enum.security import parse_security_descriptor
from base64 import b64decode

def test_certipy_json_normalization_preserves_source_and_evidence():
    snapshot = CertipyAdapter().from_json({
        "Certificate Authorities": {"0": {"CA Name": "LabCA", "DNS Name": "dc.lab"}},
        "Certificate Templates": {
            "0": {"Template Name": "Lab-ESC1", "Enabled": True,
                   "[!] Vulnerabilities": {"ESC1": "User can enroll"},
                   "Extended Key Usage": ["Client Authentication"],
                   "Certificate Authorities": ["LabCA"]},
            "1": {"Template Name": "Safe", "Enabled": True}
        }
    })
    assert snapshot.cas[0]["CA Name"] == "LabCA"
    assert snapshot.assessments["Lab-ESC1"].vulnerable is True
    assert snapshot.assessments["Lab-ESC1"].source == "certipy"
    assert snapshot.assessments["Lab-ESC1"].evidence["Certificate Authorities"] == ["LabCA"]
    assert snapshot.assessments["Safe"].vulnerable is False
    assert snapshot.normalized_cas()[0].provenance[0].source == "certipy"
    assert snapshot.normalized_templates()[0].ekus == ["1.3.6.1.5.5.7.3.2"]

def test_corroboration_exposes_disagreement():
    c = Corroboration("T", [SourceAssessment("ldap-native", True),
                             SourceAssessment("certipy", False)])
    assert c.status == "disagreement"
    assert c.as_dict()["assessments"][0]["source"] == "ldap-native"

def test_coverage_has_explicit_not_run_status():
    report = CoverageReport()
    report.add("ESC1", CoverageStatus.PASS)
    report.add("ESC2", CoverageStatus.NOT_RUN, "intentionally out of scope")
    assert report.as_dict()["ESC2"]["status"] == "NOT RUN"
    assert "intentionally out of scope" in report.render()

def test_adcs_scan_correlates_native_and_adapter_sources():
    _, cas, templates = collect_fixture("A")
    snapshot = CertipyAdapter().from_json({
        "Certificate Authorities": {},
        "Certificate Templates": {"0": {"Template Name": "Lab-ESC1",
                                            "[!] Vulnerabilities": {"ESC1": "yes"}}}
    })
    _, comparisons, coverage, _, _ = scan(cas, templates, certipy=snapshot)
    assert comparisons["Lab-ESC1"].status == "corroborated"
    assert coverage.as_dict()["AD CS / ESC2+"]["status"] == "NOT RUN"

def test_certipy_ingests_all_vulnerability_identifiers_and_levels():
    snap = CertipyAdapter().from_json({
        "Certificate Authorities": {"0": {"CA Name": "CA", "[!] Vulnerabilities": {"ESC7": "danger"}}},
        "Certificate Templates": {"0": {"Template Name": "T", "[!] Vulnerabilities": {
            "ESC15": "future", "CUSTOM-RISK": "preserved"}}}
    })
    rows = snap.vulnerability_records()
    assert {(x["rule"], x["affected_object"]) for x in rows} == {
        ("ESC7", "CA"), ("ESC15", "T"), ("CUSTOM-RISK", "T")}

def test_live_fixture_is_sanitized_and_uses_real_descriptor_shape():
    path = Path(__file__).parent / "fixtures" / "live_sccm_lab_esc1.json"
    data = json.loads(path.read_text())
    assert data["template"]["cn"] == "Snablr-ESC1-Lab"
    assert parse_security_descriptor(b64decode(data["template"]["nTSecurityDescriptorBase64"]))
    assert "password" not in path.read_text().lower()
