"""LDAPDomainDump must inherit AD-Enum's protected-LDAP decision and report why."""
import json
import stat
import sys

import pytest

import ad_enum.adapters.base as base
from ad_enum.adapters.ldapdomaindump import LDAPDomainDumpAdapter
from ad_enum.core.context import AuthContext, ScanContext
from ad_enum.core.planner import ModuleSpec, PlanStatus, PlannedModule
from ad_enum.core.workspace import ScanWorkspace
from ad_enum.external import execute_external, failure_summary

SCANNER_SECRET = "ScannerOnlySecret"


def _fake_tool(path, body):
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _context(tmp_path, *, ldaps=False, protected_ldap=False):
    workspace = ScanWorkspace(tmp_path, "example.test", scan_id="one")
    return ScanContext("example.test", "192.0.2.10",
                       AuthContext("svc-scan", SCANNER_SECRET, "EXAMPLE"), workspace,
                       timeout=10, scan_id="one", ldaps=ldaps, protected_ldap=protected_ldap)


def _ldd_invocation(tmp_path, monkeypatch, *, ldaps=False, protected_ldap=False):
    """Run the real adapter against a fake tool and return the argv it used."""
    args_file = tmp_path / "args.txt"
    tool = _fake_tool(tmp_path / "ldapdomaindump",
                      "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + str(args_file) + "\nexit 0\n")
    monkeypatch.setattr(base, "find_executable", lambda name: str(tool))
    LDAPDomainDumpAdapter().run(
        context=_context(tmp_path, ldaps=ldaps, protected_ldap=protected_ldap))
    return args_file.read_text().splitlines()


def test_plain_native_ldap_keeps_the_normal_invocation(tmp_path, monkeypatch):
    argv = _ldd_invocation(tmp_path, monkeypatch)
    assert argv[-1] == "192.0.2.10"
    assert not any("ldaps://" in part for part in argv)
    # The fake tool records arguments after argv[0].
    assert argv[:2] == ["-u", r"example.test\svc-scan"]


@pytest.mark.parametrize("negotiated", ["starttls", "ldaps"])
def test_protected_native_ldap_selects_the_ldaps_connection_string(
        tmp_path, monkeypatch, negotiated):
    argv = _ldd_invocation(tmp_path, monkeypatch, protected_ldap=True)
    # The installed tool (0.10.0) selects SSL with the ldaps:// scheme; AD-Enum
    # must not invent --ssl/--port flags that do not exist.
    assert argv[-1] == "ldaps://192.0.2.10"
    assert "--ssl" not in argv and "--port" not in argv


def test_operator_ldaps_flag_also_uses_the_protected_form(tmp_path, monkeypatch):
    argv = _ldd_invocation(tmp_path, monkeypatch, ldaps=True)
    assert argv[-1] == "ldaps://192.0.2.10"


def test_failure_summaries_are_concise_and_distinct():
    assert failure_summary(RuntimeError(
        "ldapdomaindump exited 1: LDAPStrongerAuthRequiredResult - 8 - strongerAuthRequired")
    ) == "DC requires protected LDAP"
    assert failure_summary(RuntimeError(
        "ldapdomaindump exited 1: ssl.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]")) == \
        "TLS connection failed"
    assert failure_summary(RuntimeError(
        "ldapdomaindump exited 1: ValueError: unsupported hash type MD4")) == \
        "dependency error: MD4 unavailable"
    assert failure_summary(ModuleNotFoundError("No module named 'Crypto'")) == \
        "dependency error: missing Python module"
    assert failure_summary(RuntimeError(
        "ldapdomaindump exited 1: LDAPInvalidCredentialsResult - 49 - invalidCredentials")) == \
        "authentication rejected"
    assert failure_summary(RuntimeError("ldapdomaindump exited 1: socket timeout")) == \
        "socket timeout"


def _plan(module_id, name, output):
    return PlannedModule(ModuleSpec(module_id, name, "directory", outputs=(output,)),
                         PlanStatus.READY)


def _failing_ldd(tmp_path, monkeypatch):
    """Fail exactly like the hardened DC does, echoing argv (with the password)."""
    tool = _fake_tool(tmp_path / "ldapdomaindump",
                      "#!/bin/sh\n"
                      "printf '%s\\n' \"$@\" >&2\n"
                      "echo 'LDAPStrongerAuthRequiredResult - 8 - strongerAuthRequired' >&2\n"
                      "exit 1\n")
    monkeypatch.setattr(base, "find_executable", lambda name: str(tool))
    return tool


def test_protected_failure_is_a_single_surfaced_reason_without_scanner_secrets(
        tmp_path, monkeypatch):
    _failing_ldd(tmp_path, monkeypatch)
    context = _context(tmp_path, protected_ldap=True)
    messages = []

    results, _ = execute_external(
        context, [_plan("ldapdomaindump", "LDAPDomainDump", "LDAPDomainDump")],
        progress=lambda stage, label, state=None, line=None:
            messages.append((stage, label, state, line)))

    assert results["ldapdomaindump"]["status"] == "FAILED"
    assert ("end", "LDAPDomainDump", "FAILED", "DC requires protected LDAP") in messages
    failure = json.loads(
        (context.workspace.root / "LDAPDomainDump" / "raw" / "failure.json").read_text())
    assert failure["summary"] == "DC requires protected LDAP"
    assert SCANNER_SECRET not in json.dumps(failure)
    assert "<redacted>" in failure["reason"]
    assert "Traceback" not in failure["summary"]


def test_failing_collector_does_not_erase_other_collector_evidence(tmp_path, monkeypatch):
    _failing_ldd(tmp_path, monkeypatch)
    netexec = _fake_tool(tmp_path / "nxc", "#!/bin/sh\nexit 0\n")
    real_lookup = base.find_executable
    monkeypatch.setattr(base, "find_executable",
                        lambda name: str(netexec) if name == "nxc" else real_lookup(name))
    context = _context(tmp_path, protected_ldap=True)

    results, _ = execute_external(context, [
        _plan("ldapdomaindump", "LDAPDomainDump", "LDAPDomainDump"),
        _plan("netexec", "NetExec", "NetExec")])

    assert results["ldapdomaindump"]["status"] == "FAILED"
    assert results["netexec"]["status"] == "PASS"
    assert (context.workspace.root / "LDAPDomainDump" / "raw" / "failure.json").is_file()


def test_console_reports_the_real_reason_instead_of_plain_failure(
        tmp_path, monkeypatch, capsys):
    from ad_enum import cli
    from test_pipeline_smoke import FakeCollector

    _failing_ldd(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "Collector", FakeCollector)
    monkeypatch.setattr(cli, "probe_anonymous_ldap",
                        lambda *a, **k: {"bind": "DENIED", "rootdse": "DENIED",
                                         "domain_data": "DENIED", "sources": ["t"]})
    monkeypatch.setattr(cli, "probe_anonymous_smb",
                        lambda *a, **k: {"session": "DENIED", "share_enumeration": "DENIED",
                                         "shares": [], "sources": ["t"]})
    monkeypatch.setattr(cli, "collect_sysvol", lambda *a, **k: {"status": "PASS", "files": []})
    monkeypatch.setattr(cli, "collect_netlogon", lambda *a, **k: {"status": "PASS", "files": []})
    monkeypatch.setattr(cli, "discover_sccm", lambda *a, **k: {
        "hosts": [], "management_points": [], "distribution_points": [], "site_servers": [],
        "sms_providers": [], "sql_servers": [], "sup_wsus": [],
        "pxe": {"status": "UNKNOWN"}, "status": "sccm-publication-and-inventory"})
    monkeypatch.setattr(cli, "probe_management_points", lambda *a, **k: [])
    monkeypatch.setattr(cli, "pxethief_capability", lambda *a, **k: {"status": "PASS", "detail": "x"})
    monkeypatch.setattr(cli, "run_pxethief", lambda *a, **k: {})
    monkeypatch.setattr(cli, "sccmhunter_capability", lambda *a, **k: {"status": "PASS", "detail": "x"})
    monkeypatch.setattr(cli, "run_sccmhunter", lambda *a, **k: {
        "status": "NOT TESTED", "source": "", "command": "", "commit": "", "errors": ["x"],
        "site_codes": [], "management_points": [], "distribution_points": [], "site_servers": []})
    monkeypatch.setattr(cli, "sccmsecrets_capability", lambda *a, **k: {"status": "PASS", "detail": "x"})
    monkeypatch.setattr(cli, "run_sccmsecrets_files", lambda *a, **k: {})
    monkeypatch.setattr(sys, "argv", ["ad-enum.py", "-u", "svc-scan", "-p", SCANNER_SECRET,
                                      "-domain", "sccm.lab", "-dc-ip", "192.0.2.10",
                                      "--modules", "ldapdomaindump", "--output-dir", str(tmp_path),
                                      "--no-color"])

    assert cli.main() == 0
    console = capsys.readouterr().out

    assert "LDAPDomainDump failed — DC requires protected LDAP" in console
    assert "LDAPDomainDump failed — continuing" not in console
    assert "Traceback" not in console
