import copy
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


def test_real_certipy_text_evidence_reaches_compact_esc7_without_losing_evidence():
    snapshot = CertipyAdapter().from_text(REAL_CERTIPY_FIXTURE.read_text())
    record = snapshot.vulnerability_records()[0]
    finding = {
        "category": record["category"], "rule": record["rule"],
        "title": f"{record['rule']} — {record['affected_object']}",
        "status": "single-source", "sources": [{"source": record["source"], "vulnerable": True}],
        "evidence": {"certipy": record["evidence"]},
    }
    output = "\n".join(_finding_lines([finding]))

    assert "ESC7 VULNERABLE — Example-CA" in output
    assert "    CA DNS  ca1.example.test" in output
    assert "    Status  SINGLE-SOURCE" in output
    assert "    Source  Certipy" in output
    # CA ACL mechanics are not repeated in the concise operator view...
    assert "Effective principal" not in output
    assert "Rights" not in output
    assert "EXAMPLE\\Domain Admins" not in output
    # ...but the structured evidence is untouched.
    assert finding["evidence"]["certipy"]["Access Rights"]["ManageCa"] == [
        r"EXAMPLE\Administrators", r"EXAMPLE\Domain Admins", r"EXAMPLE\Enterprise Admins"]


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

    assert "    Note    Certipy could not enumerate certificate templates" in output
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


def test_esc1_rendering_is_concise_and_drops_predicate_mechanics():
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

    assert "ESC1 VULNERABLE — Example-ESC1-Template" in output
    assert "    CA      Example-CA" in output
    assert "    CA DNS  ca1.example.test" in output
    assert "    Status  SINGLE-SOURCE" in output
    assert "    Source  Native AD-Enum" in output
    assert "    Note    Certipy could not enumerate certificate templates" in output
    # Predicate mechanics and the redundant template field stay out of normal output.
    assert "Enrollee supplies subject" not in output
    assert "Client authentication" not in output
    assert "Low-priv enroll" not in output
    assert "Template " not in output
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

    assert "ESC1 DISAGREEMENT — Example-ESC1-Template" in output
    assert "Certipy did not classify this template as ESC1" in output
    assert "Certipy could not enumerate certificate templates" not in output
    # A disagreement is not labelled vulnerable and does not repeat the status field.
    assert "VULNERABLE" not in output
    assert "Status" not in output


def test_esc7_rendering_is_compact_and_keeps_evidence_structured():
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

    assert "ESC7 VULNERABLE — Example-CA" in output
    assert "    CA DNS  ca1.example.test" in output
    assert "    Status  SINGLE-SOURCE" in output
    assert "    Source  Certipy" in output
    # CA ACL mechanics belong in structured evidence, not the concise view.
    assert "Effective principal" not in output
    assert "Rights" not in output
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
    expected_rows = [
        "    CA      Example-CA", "    CA DNS  ca1.example.test", "    Status  CONFIRMED",
        "    Source  Native AD-Enum", "    CA DNS  ca7.example.test",
        "    Status  SINGLE-SOURCE", "    Source  Certipy",
    ]
    for row in expected_rows:
        assert row in output

    def value_column(value):
        position = output.index(value)
        return position - output.rindex("\n", 0, position) - 1

    # Every ADCS field block shares one value column.
    assert len({value_column(value) for value in
                ("Example-CA", "ca1.example.test", "ca7.example.test")}) == 1


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

    assert "ESC7 VULNERABLE — Example-CA" in report
    assert "CA DNS" in report and "ca1.example.test" in report
    assert "\033[" not in report


def _esc4_finding(name, *, status="single-source", source="certipy"):
    return {
        "category": "ADCS", "rule": "ESC4", "title": f"ESC4 — {name}",
        "status": status, "sources": [{"source": source, "vulnerable": True}],
        "evidence": {"certipy": {"Template Name": name}},
    }


def test_esc8_renders_compact_web_enrollment_fields():
    finding = {
        "category": "ADCS", "rule": "ESC8", "title": "ESC8 — Example-CA",
        "status": "single-source", "sources": [{"source": "certipy", "vulnerable": True}],
        "evidence": {"certipy": {
            "CA Name": "Example-CA", "DNS Name": "ca1.example.test",
            "Web Enrollment": {"http": {"enabled": True, "channel_binding": False},
                               "https": {"enabled": False, "channel_binding": True}},
        }},
    }
    output = "\n".join(_finding_lines([finding]))

    assert "ESC8 VULNERABLE — Example-CA" in output
    assert "    CA DNS  ca1.example.test" in output
    assert "    HTTP    ENABLED" in output
    assert "    HTTPS   DISABLED" in output
    assert "    Status  SINGLE-SOURCE" in output
    assert "    Source  Certipy" in output
    assert "channel binding" not in output
    assert "Impact" not in output


def test_esc4_findings_are_grouped_with_deterministic_ordering():
    names = ["ADEnum-ESC1-Positive", "ADEnum-ESC1-Denied", "ADEnum-ESC1-Approval",
             "ADEnum-ESC1-NoEnroll", "ADEnum-ESC1-NoAuthEKU", "ADEnum-ESC1-Signatures",
             "ADEnum-ESC1-Unpublished"]
    output = "\n".join(_finding_lines([_esc4_finding(name) for name in names]))

    assert "ESC4 VULNERABLE — 7 templates" in output
    assert "    Templates" in output
    listed = [line.strip() for line in output.splitlines() if line.strip().startswith("ADEnum-")]
    assert listed == sorted(names, key=str.casefold)
    assert output.count("ESC4 VULNERABLE") == 1  # one grouped block, not seven

    shuffled = "\n".join(_finding_lines([_esc4_finding(name) for name in reversed(names)]))
    assert shuffled == output


def test_esc4_grouping_keeps_source_variation_visible():
    finding = [_esc4_finding("A-Template"), _esc4_finding("B-Template", source="ldap-native")]
    output = "\n".join(_finding_lines(finding))

    assert "ESC4 VULNERABLE — 2 templates" in output
    assert "A-Template" in output and "Certipy" in output
    assert "B-Template" in output and "Native AD-Enum" in output


def test_adcs_rendering_leaves_structured_findings_untouched():
    findings = [
        {"category": "ADCS", "rule": "ESC1", "title": "ESC1 — Example-Template",
         "status": "single-source", "sources": [{"source": "ldap-native", "vulnerable": True}],
         "evidence": {"ca_name": "Example-CA", "ca_dns": "ca1.example.test",
                      "enrollee_supplies_subject": True, "client_authentication": True,
                      "low_privilege_enrollment": True}},
        {"category": "ADCS", "rule": "ESC7", "title": "ESC7 — Example-CA",
         "status": "single-source", "sources": [{"source": "certipy", "vulnerable": True}],
         "evidence": {"certipy": {"DNS Name": "ca1.example.test"}}},
        _esc4_finding("Example-ESC4"),
    ]
    snapshot = copy.deepcopy(findings)
    _finding_lines(findings)

    assert findings == snapshot
    assert len(findings) == 3


def test_results_txt_adcs_is_concise_and_ansi_free(tmp_path):
    finding = {
        "category": "ADCS", "rule": "ESC1", "title": "ESC1 — Example-ESC1-Template",
        "status": "single-source", "sources": [{"source": "ldap-native", "vulnerable": True}],
        "evidence": {"ca_name": "Example-CA", "ca_dns": "ca1.example.test",
                     "enrollee_supplies_subject": True, "client_authentication": True,
                     "low_privilege_enrollment": True, "source": "Native AD-Enum"},
    }
    report = _results_text("example.test", "dc1.example.test", {}, DomainInventory(), [], [],
                           [finding], ScanWorkspace(tmp_path, "example.test"))

    assert "ESC1 VULNERABLE — Example-ESC1-Template" in report
    assert "Enrollee supplies subject" not in report
    assert "Client authentication" not in report
    assert "Low-priv enroll" not in report
    assert "\033[" not in report
