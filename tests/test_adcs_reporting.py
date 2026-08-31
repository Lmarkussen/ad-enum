from ad_enum.adapters.certipy import CertipyAdapter
from ad_enum.cli import _finding_lines, _results_text
from ad_enum.core.workspace import ScanWorkspace
from ad_enum.inventory import DomainInventory


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

    assert "CA                    Example-CA" in output
    assert "CA DNS                ca1.example.test" in output
    assert "Template              Example-ESC1-Template" in output
    assert "Enrollee supplies subject  ENABLED" in output
    assert "Client authentication  ENABLED" in output
    assert "Low-priv enroll       YES" in output
    assert "Source                Native AD-Enum" in output
    assert "Certipy could not enumerate certificate templates" in output
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

    assert "CA                   Example-CA" in output
    assert "CA DNS               ca1.example.test" in output
    assert "Effective principal  EXAMPLE\\Operators" in output
    assert "Rights               ManageCA, ManageCertificates" in output
    assert "Status               SINGLE-SOURCE" in output
    assert "Source               Certipy" in output
    assert "EXAMPLE\\Domain Admins" not in output


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
