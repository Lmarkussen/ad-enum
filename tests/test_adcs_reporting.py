from pathlib import Path

from ad_enum.adapters.certipy import CertipyAdapter
from ad_enum.cli import _finding_lines, _results_text
from ad_enum.core.workspace import ScanWorkspace
from ad_enum.inventory import DomainInventory


REAL_CERTIPY_FIXTURE = Path(__file__).parent / "fixtures" / "certipy_real_format.txt"


def test_real_certipy_text_format_preserves_ca_evidence_and_template_failure():
    snapshot = CertipyAdapter().from_json(REAL_CERTIPY_FIXTURE)

    assert snapshot.template_enumeration_state == "UNAVAILABLE"
    assert len(snapshot.cas) == 1
    ca = snapshot.cas[0]
    assert ca["CA Name"] == "Example-CA"
    assert ca["DNS Name"] == "ca1.example.test"
    assert ca["Owner"] == r"EXAMPLE\Administrators"
    assert ca["Access Rights"]["ManageCa"] == [
        r"EXAMPLE\Administrators", r"EXAMPLE\Domain Admins", r"EXAMPLE\Enterprise Admins"]
    assert ca["Access Rights"]["ManageCertificates"] == [
        r"EXAMPLE\Administrators", r"EXAMPLE\Domain Admins", r"EXAMPLE\Enterprise Admins"]
    assert ca["Access Rights"]["Enroll"] == [r"EXAMPLE\Authenticated Users"]
    assert ca["User ACL Principals"] == [r"EXAMPLE\Administrators"]
    records = snapshot.vulnerability_records()
    assert len(records) == 1
    assert records[0]["rule"] == "ESC7"
    normalized = snapshot.normalized_cas()[0]
    assert normalized.name == "Example-CA"
    assert normalized.hostname == "ca1.example.test"
    assert normalized.evidence["raw"]["User ACL Principals"] == [r"EXAMPLE\Administrators"]


def test_real_certipy_text_evidence_fills_json_snapshot_without_replacing_primary_data():
    adapter = CertipyAdapter()
    snapshot = adapter.from_json({
        "Certificate Authorities": {"0": {"CA Name": "Example-CA"}},
        "Certificate Templates": {},
    })
    text_snapshot = adapter.from_text(REAL_CERTIPY_FIXTURE.read_text())

    adapter._merge_text_data(snapshot, text_snapshot)

    assert snapshot.cas[0]["DNS Name"] == "ca1.example.test"
    assert snapshot.cas[0]["User ACL Principals"] == [r"EXAMPLE\Administrators"]
    assert snapshot.template_enumeration_state == "UNAVAILABLE"
    assert snapshot.raw_data["Certificate Authorities"]["0"]["CA Name"] == "Example-CA"


def test_real_certipy_text_evidence_reaches_esc7_renderer_and_filters_acl_principals():
    snapshot = CertipyAdapter().from_text(REAL_CERTIPY_FIXTURE.read_text())
    record = snapshot.vulnerability_records()[0]
    finding = {
        "category": record["category"], "rule": record["rule"],
        "title": f"{record['rule']} — {record['affected_object']}",
        "status": "single-source", "sources": [{"source": record["source"], "vulnerable": True}],
        "evidence": {"certipy": record["evidence"]},
    }
    output = "\n".join(_finding_lines([finding]))

    assert "CA                         Example-CA" in output
    assert "CA DNS                     ca1.example.test" in output
    assert r"Effective principal        EXAMPLE\Administrators" in output
    assert "Rights                     ManageCA, ManageCertificates" in output
    assert "EXAMPLE\\Domain Admins" not in output
    assert "EXAMPLE\\Enterprise Admins" not in output
    assert "Enroll" not in output


def test_real_certipy_template_failure_drives_accurate_esc1_note():
    snapshot = CertipyAdapter().from_text(REAL_CERTIPY_FIXTURE.read_text())
    finding = {
        "category": "ADCS", "rule": "ESC1", "title": "ESC1 — Example-ESC1-Template",
        "status": "single-source", "sources": [{"source": "ldap-native", "vulnerable": True}],
        "evidence": {
            "ca_name": "Example-CA", "ca_dns": "ca1.example.test",
            "template": "Example-ESC1-Template",
            "certipy_template_enumeration": snapshot.template_enumeration_state,
        },
    }
    output = "\n".join(_finding_lines([finding]))

    assert "Note                       Certipy could not enumerate certificate templates" in output
    assert "did not classify this template" not in output


def test_certipy_empty_template_section_is_retained_as_unavailable():
    snapshot = CertipyAdapter().from_json({
        "Certificate Authorities": {"0": {
            "CA Name": "Example-CA", "DNS Name": "ca1.example.test",
            "Owner": "EXAMPLE\\Administrators",
            "Access Rights": {"ManageCA": ["EXAMPLE\\Operators"]},
        }},
        "Certificate Templates": {},
    })

    assert snapshot.template_enumeration_state == "UNAVAILABLE"
    assert snapshot.normalized_cas()[0].evidence["raw"]["CA Name"] == "Example-CA"
    assert snapshot.raw_data["Certificate Authorities"]["0"]["Owner"] == "EXAMPLE\\Administrators"


def test_esc1_rendering_surfaces_native_context_and_certipy_limitation():
    finding = {
        "category": "ADCS", "rule": "ESC1", "title": "ESC1 — Example-ESC1-Template",
        "status": "single-source", "sources": [{"source": "ldap-native", "vulnerable": True}],
        "evidence": {
            "ca_name": "Example-CA", "ca_dns": "ca1.example.test",
            "template": "Example-ESC1-Template",
            "enrollee_supplies_subject": True, "client_authentication": True,
            "low_privilege_enrollment": True, "source": "Native AD-Enum",
            "certipy_template_enumeration": "UNAVAILABLE",
        },
    }
    output = "\n".join(_finding_lines([finding]))

    assert "CA                         Example-CA" in output
    assert "CA DNS                     ca1.example.test" in output
    assert "Template                   Example-ESC1-Template" in output
    assert "Enrollee supplies subject  ENABLED" in output
    assert "Client authentication      ENABLED" in output
    assert "Low-priv enroll            YES" in output
    assert "Source                     Native AD-Enum" in output
    assert "Note                       Certipy could not enumerate certificate templates" in output
    assert "Certipy did not classify this template as ESC1" not in output


def test_esc1_active_certipy_disagreement_is_distinguished_from_unavailable():
    finding = {
        "category": "ADCS", "rule": "ESC1", "title": "ESC1 — Example-ESC1-Template",
        "status": "disagreement", "sources": [
            {"source": "ldap-native", "vulnerable": True},
            {"source": "certipy", "vulnerable": False},
        ],
        "evidence": {
            "ca_name": "Example-CA", "template": "Example-ESC1-Template",
            "certipy_template_enumeration": "AVAILABLE",
            "certipy_template_evaluated": True, "certipy_esc1": False,
        },
    }
    output = "\n".join(_finding_lines([finding]))

    assert "Certipy did not classify this template as ESC1" in output
    assert "Certipy could not enumerate certificate templates" not in output


def test_esc7_rendering_uses_effective_principal_and_matching_rights():
    finding = {
        "category": "ADCS", "rule": "ESC7", "title": "ESC7 — Example-CA",
        "status": "single-source", "sources": [{"source": "certipy", "vulnerable": True}],
        "evidence": {"certipy": {
            "CA Name": "Example-CA", "DNS Name": "ca1.example.test",
            "Owner": "EXAMPLE\\Administrators",
            "Access Rights": {
                "ManageCa": ["EXAMPLE\\Operators", "EXAMPLE\\Domain Admins"],
                "ManageCertificates": ["EXAMPLE\\Operators", "EXAMPLE\\Domain Admins"],
            },
            "User ACL Principals": ["EXAMPLE\\Operators"],
            "[!] Vulnerabilities": {"ESC7": "User has dangerous permissions."},
        }},
    }
    output = "\n".join(_finding_lines([finding]))

    assert "CA                         Example-CA" in output
    assert "CA DNS                     ca1.example.test" in output
    assert "Effective principal        EXAMPLE\\Operators" in output
    assert "Rights                     ManageCA, ManageCertificates" in output
    assert "Status                     SINGLE-SOURCE" in output
    assert "Source                     Certipy" in output
    assert "EXAMPLE\\Domain Admins" not in output


def test_adcs_findings_share_one_value_column_for_long_and_short_labels():
    findings = [
        {"category": "ADCS", "rule": "ESC1", "title": "ESC1 — Example-Template",
         "status": "confirmed", "sources": [{"source": "ldap-native"}],
         "evidence": {"ca_name": "Example-CA", "ca_dns": "ca1.example.test",
                      "template": "Example-Template", "enrollee_supplies_subject": True}},
        {"category": "ADCS", "rule": "ESC7", "title": "ESC7 — Example-CA",
         "status": "single-source", "sources": [{"source": "certipy"}],
         "evidence": {"certipy": {"CA Name": "Example-CA-7", "DNS Name": "ca7.example.test",
                                    "User ACL Principals": [r"EXAMPLE\Operators"]}}},
    ]
    output = "\n".join(_finding_lines(findings))
    rows = [line for line in output.splitlines()
            if any(line.lstrip().startswith(label) for label in ("CA", "CA DNS", "Template"))]

    assert len({line.index(value) for line, value in zip(rows, [
        "Example-CA", "ca1.example.test", "Example-Template",
        "Example-CA-7", "ca7.example.test"])}) == 1


def test_adcs_details_are_present_in_results_txt_without_changing_findings(tmp_path):
    finding = {
        "category": "ADCS", "rule": "ESC7", "title": "ESC7 — Example-CA",
        "status": "single-source", "sources": [{"source": "certipy", "vulnerable": True}],
        "evidence": {"certipy": {
            "CA Name": "Example-CA", "DNS Name": "ca1.example.test",
            "Access Rights": {"ManageCA": ["EXAMPLE\\Operators"]},
            "User ACL Principals": ["EXAMPLE\\Operators"],
        }},
    }
    report = _results_text("example.test", "dc1.example.test", {}, DomainInventory(), [], [],
                           [finding], ScanWorkspace(tmp_path, "example.test"))

    assert "Effective principal" in report
    assert "ManageCA" in report
    assert "\033[" not in report
