from ad_enum.core.context import AuthContext, ScanContext
from ad_enum.core.corroboration import Corroboration
from ad_enum.core.planner import ExecutionPlanner, PlanStatus
from ad_enum.adapters.base import ToolAdapter
from ad_enum.adapters.bloodhound import BloodHoundAdapter
from ad_enum.adapters.ldapdomaindump import LDAPDomainDumpAdapter
from ad_enum.adapters.netexec import NetExecAdapter

def test_planner_marks_missing_tool_unavailable():
    plan = ExecutionPlanner(executable_lookup=lambda name: "/bin/true" if name in {"certipy", "nxc"} else None).plan(["adcs-certipy", "netexec", "bloodhound"])
    assert plan[0].status == PlanStatus.READY
    assert plan[1].status == PlanStatus.READY
    assert plan[2].status == PlanStatus.UNAVAILABLE

def test_scan_context_redacts_secret():
    auth = AuthContext("u", "secret", "d")
    assert "secret" not in repr(auth)
    assert auth.redacted()["password"] == "<redacted>"

def test_live_confirmed_disagreement_is_distinct():
    c = Corroboration("T")
    from ad_enum.core.corroboration import SourceAssessment
    c.assessments = [SourceAssessment("ldap-native", True), SourceAssessment("certipy", False)]
    c.add_validation("certificate-enrollment", "confirmed")
    assert c.status == "disagreement"
    assert c.overall_status == "live-confirmed disagreement"

def test_adapter_commands_redact_password_and_use_owned_tools():
    assert "secret" not in " ".join(ToolAdapter.redact_command(["tool", "-p", "secret"], ["secret"]))
    bh = BloodHoundAdapter().build_command(domain="d", username="u", password="p", dc_ip="1.2.3.4", output_dir="x")
    assert bh[0] == "bloodhound-python" and "p" not in ToolAdapter.redact_command(bh, ["p"])
    assert LDAPDomainDumpAdapter().build_command(domain="d", username="u", password="p", dc_ip="1.2.3.4", output_dir="x")[0] == "ldapdomaindump"
    assert NetExecAdapter().build_command(username="u", password="p", target="1.2.3.4")[0] == "nxc"

def test_adapter_execution_timeout_is_explicit():
    import sys
    try:
        ToolAdapter().execute([sys.executable, "-c", "import time; time.sleep(1)"], timeout=0.01)
    except TimeoutError as exc:
        assert "timed out" in str(exc)
    else:
        raise AssertionError("timeout was not reported")
