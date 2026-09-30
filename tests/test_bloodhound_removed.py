"""Contract tests: BloodHound is no longer an active AD-Enum collector.

BloodHound used to be scheduled, executed, required, and installed as part of a
normal scan.  These tests pin the new contract: it is none of those things, yet
native findings and any historical-artifact reader keep working without it.
"""
from pathlib import Path

import ad_enum.adapters as adapters
from ad_enum import external
from ad_enum.cli import _results_text
from ad_enum.core.planner import ExecutionPlanner, ModuleRegistry
from ad_enum.core.workspace import ScanWorkspace
from ad_enum.delegation import enumerate_delegation
from ad_enum.doctor import REQUIRED_TOOLS
from ad_enum.inventory import DomainInventory, native_inventory
from ad_enum.kerberos import roastable


def test_bloodhound_is_not_registered_or_scheduled():
    registry = ModuleRegistry.default()
    assert "bloodhound" not in registry.modules
    plan = ExecutionPlanner(executable_lookup=lambda name: "/bin/true").plan()
    assert all(item.spec.id != "bloodhound" for item in plan)
    assert not any("bloodhound" in item.spec.name.lower() for item in plan)


def test_bloodhound_adapter_is_gone():
    assert not hasattr(adapters, "BloodHoundAdapter")
    assert "BloodHoundAdapter" not in adapters.__all__
    assert "bloodhound" not in external.ADAPTERS


def test_doctor_does_not_require_bloodhound():
    commands = {command for _, command, _, _ in REQUIRED_TOOLS}
    assert "bloodhound-python" not in commands


def test_missing_bloodhound_executable_does_not_break_planning():
    # A machine without bloodhound-python must plan cleanly and never surface it.
    plan = ExecutionPlanner(executable_lookup=lambda name: None).plan()
    assert plan  # other modules still exist
    assert not any(item.spec.id == "bloodhound" for item in plan)


def test_installer_does_not_provision_bloodhound():
    script = (Path(__file__).resolve().parents[1] / "install.sh").read_text(encoding="utf-8")
    assert "bloodhound" not in script.lower()


def test_collector_summary_never_lists_bloodhound(tmp_path):
    # Even if legacy scan data still carries a BloodHound entry, it must not be
    # rendered as a normal collector.
    workspace = ScanWorkspace(tmp_path, "sccm.lab", scan_id="scan-one")
    report = _results_text("SCCM.LAB", "dc.sccm.lab",
                           {"bloodhound": {"status": "PASS"}, "adcs-certipy": {"status": "PASS"}},
                           DomainInventory(), [], [], [], workspace)
    collectors = report.split("Collectors\n", 1)[1].split("\nInventory", 1)[0]
    assert "BloodHound" not in collectors
    assert "Certipy" in collectors


def test_native_kerberos_findings_survive_without_bloodhound():
    raw = {"defaultNamingContext": "DC=example,DC=test", "identities": [
        {"objectClass": ["user"], "objectSid": "S-1-5-21-1-2-3-1101",
         "sAMAccountName": "svc-sql",
         "servicePrincipalName": ["MSSQLSvc/sql.example.test:1433"],
         "userAccountControl": 512}]}
    inventory = native_inventory(raw)
    exposure = roastable(inventory)
    assert [item.username for item in exposure["kerberoast"]] == ["svc-sql"]
    # Source attribution stays truthful: native LDAP only, not a faked corroboration.
    assert exposure["kerberoast"][0].sources == ["native-ldap"]


def test_native_delegation_findings_survive_without_bloodhound():
    raw = {"defaultNamingContext": "DC=example,DC=test", "identities": [
        {"objectClass": ["user"], "objectSid": "S-1-5-21-1-2-3-1201",
         "sAMAccountName": "svc-app",
         "msDS-AllowedToDelegateTo": ["CIFS/dc.example.test"],
         "userAccountControl": 512}]}
    records = enumerate_delegation(native_inventory(raw))
    constrained = [r for r in records if r.kind == "constrained"]
    assert [r.target for r in constrained] == ["svc-app"]
    assert constrained[0].sources == ["native-ldap"]
