"""External collectors must never persist the scanner password in failure text."""
import json
import stat
import sys
from pathlib import Path

import pytest

import ad_enum.adapters.base as base
from ad_enum.adapters.base import ToolAdapter
from ad_enum.adapters.certipy import CertipyAdapter
from ad_enum.core.context import AuthContext, ScanContext
from ad_enum.core.planner import ModuleSpec, PlanStatus, PlannedModule
from ad_enum.core.workspace import ScanWorkspace
from ad_enum.external import execute_external

SECRET = "ScannerOnlySecret"


class _Adapter(ToolAdapter):
    source_name = "fixture"
    executable = "fixture-tool"


def test_execute_failure_message_redacts_secrets():
    script = f"import sys; sys.stderr.write('boom {SECRET}\\n'); sys.exit(2)"
    with pytest.raises(RuntimeError) as excinfo:
        _Adapter().execute([sys.executable, "-c", script], timeout=10, secrets=(SECRET,))

    message = str(excinfo.value)
    assert SECRET not in message and "<redacted>" in message


def _fake_tool(path, *, body='#!/bin/sh\nprintf \'%s\\n\' "$@" >&2\nexit 2\n'):
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


def test_collector_failure_artifact_never_persists_the_scanner_password(tmp_path, monkeypatch):
    tool = _fake_tool(tmp_path / "ldapdomaindump")
    monkeypatch.setattr(base, "find_executable", lambda name: str(tool))
    workspace = ScanWorkspace(tmp_path, "example.test", scan_id="one")
    context = ScanContext("example.test", "192.0.2.10", AuthContext("svc-scan", SECRET, "EXAMPLE"),
                          workspace, timeout=10, scan_id="one")
    plan = [PlannedModule(ModuleSpec("ldapdomaindump", "LDAPDomainDump", "directory",
                                     required_tools=("ldapdomaindump",), outputs=("LDAPDomainDump",)),
                          PlanStatus.READY)]

    results, diagnostics = execute_external(context, plan)

    assert results["ldapdomaindump"]["status"] == "FAILED"
    persisted = (workspace.root / "LDAPDomainDump" / "raw" / "failure.json").read_text()
    assert SECRET not in persisted and "<redacted>" in persisted
    assert SECRET not in json.dumps(results) and SECRET not in " ".join(diagnostics)


def test_certipy_failure_message_redacts_the_password(tmp_path):
    tool = _fake_tool(tmp_path / "certipy")

    with pytest.raises(RuntimeError) as excinfo:
        CertipyAdapter().run(domain="example.test", username="svc-scan", password=SECRET,
                             dc_ip="192.0.2.10", executable=str(tool), timeout=10)

    message = str(excinfo.value)
    assert SECRET not in message and "<redacted>" in message
