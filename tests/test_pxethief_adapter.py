"""Focused tests for the PXEThief-backed SCCM/PXE validation adapter."""
import json
import subprocess
from pathlib import Path

from ad_enum import pxethief_adapter as px
from ad_enum.sccm import pxe_candidates
from ad_enum.sccm_models import normalize_pxe_validation


VULNERABLE_OUTPUT = """
[+] Generating and downloading encrypted media variables file from MECM server located at 192.0.2.41
[+] Using interface: eth0 - eth0
[+] Targeting user-specified host: 192.0.2.41

[!] Variables File Location: \\SMS\\variables.dat
[!] BCD File Location: \\SMS\\boot.bcd
[!] Blank password on PXE boot found!
[!] Attempting automatic exploitation.
[!] Possible credential fields found!

In TS Step "Apply Windows Settings":
OSDLocalAdminPassword - ExampleLocalAdminSecret

In TS Step "Apply Network Settings":
OSDJoinAccount - EXAMPLE\\svc-naa
OSDJoinPassword - ExampleJoinSecret
[!] Network Access Account Username: 'EXAMPLE\\svc-naa'
[!] Network Access Account Password: 'ExampleNaaSecret'
"""

NOT_VULNERABLE_OUTPUT = """
[+] Using interface: eth0 - eth0
[!] Variables File Location: \\SMS\\variables.dat
[!] BCD File Location: \\SMS\\boot.bcd
[+] User configured password detected for task sequence media. Attempts can be made to crack this password
"""

NO_RESPONSE_OUTPUT = """
[+] Using interface: eth0 - eth0
[-] No DHCP responses recieved from MECM server 192.0.2.41. This may indicate the wrong IP
"""

PERMISSION_OUTPUT = """
PermissionError: [Errno 1] Operation not permitted
"""


def _fake_pxethief(tmp_path, monkeypatch, output="", exit_code=0):
    root = tmp_path / "PXEThief"
    (root / ".venv" / "bin").mkdir(parents=True)
    interpreter = root / ".venv" / "bin" / "python3"
    interpreter.write_text(f"#!/bin/sh\ncat <<'PXEOF'\n{output}\nPXEOF\nexit {exit_code}\n")
    interpreter.chmod(0o755)
    (root / "pxethief.py").write_text("# fixture\n")
    monkeypatch.setenv("PXETHIEF_ROOT", str(root))
    return root


def test_parser_reports_vulnerable_media_and_deduplicates_material():
    result = px.parse_pxethief_output(VULNERABLE_OUTPUT)

    assert result["state"] == "VULNERABLE"
    assert result["interface"] == "eth0"
    assert result["media_file"] == r"\SMS\variables.dat"
    assert result["bcd_file"] == r"\SMS\boot.bcd"
    names = [x["name"] for x in result["task_sequence_credentials"]]
    assert names == ["OSDLocalAdminPassword", "OSDJoinAccount", "OSDJoinPassword"]
    assert result["network_access_accounts"] == [
        {"name": "NetworkAccessAccount", "username": r"EXAMPLE\svc-naa", "value": "ExampleNaaSecret"}]


def test_parser_reports_configured_password_as_not_vulnerable():
    result = px.parse_pxethief_output(NOT_VULNERABLE_OUTPUT)
    assert result["state"] == "NOT VULNERABLE"
    assert result["task_sequence_credentials"] == []


def test_parser_reports_unreachable_dp_and_permission_failure_as_not_tested():
    no_response = px.parse_pxethief_output(NO_RESPONSE_OUTPUT)
    assert no_response["state"] == "NOT TESTED"
    assert any("No DHCP responses" in error for error in no_response["errors"])

    denied = px.parse_pxethief_output(PERMISSION_OUTPUT)
    assert denied["state"] == "NOT TESTED"
    reason = " ".join(denied["errors"])
    assert "CAP_NET_RAW" in reason and "root" in reason
    # Proven against PR #11 mode 2: only CAP_NET_RAW is required, and the tool
    # does not sniff for this failure.
    assert "CAP_NET_ADMIN" not in reason
    assert "packet capture" not in reason.lower()


def test_unprivileged_run_is_attempted_and_its_permission_error_is_normalized(tmp_path, monkeypatch):
    _fake_pxethief(tmp_path, monkeypatch, output=PERMISSION_OUTPUT, exit_code=1)
    workdir = tmp_path / "work"

    result = px.run_pxethief("192.0.2.41", timeout=10, workdir=workdir)

    assert result["state"] == "NOT TESTED"
    assert "raw-socket privilege (root or CAP_NET_RAW)" in result["errors"][0]
    # The interpreter really ran, i.e. AD-Enum has no pre-execution privilege gate.
    assert "PermissionError" in (workdir / "stdout.txt").read_text()


def test_run_pxethief_uses_isolated_venv_and_keeps_raw_output_in_artifacts(tmp_path, monkeypatch):
    _fake_pxethief(tmp_path, monkeypatch, output=VULNERABLE_OUTPUT)
    workdir = tmp_path / "work"
    result = px.run_pxethief("192.0.2.41", timeout=15, workdir=workdir)

    assert result["state"] == "VULNERABLE"
    assert result["source"] == "PXEThief" and result["recovered_count"] == 4
    assert "stdout" not in result and "stderr" not in result
    assert (workdir / "settings.ini").is_file()
    raw = (workdir / "stdout.txt").read_text()
    assert "Blank password on PXE boot found" in raw
    assert json.loads((workdir / "run.json").read_text())["state"] == "VULNERABLE"


def test_run_pxethief_reports_unavailable_tool_without_fabricating_state(tmp_path, monkeypatch):
    monkeypatch.setenv("PXETHIEF_ROOT", str(tmp_path / "missing"))
    result = px.run_pxethief("192.0.2.41", timeout=5, workdir=tmp_path / "work")
    assert result["state"] == "NOT TESTED"
    assert result["source"] == "" and "PXEThief unavailable" in result["errors"][0]


def test_installer_pins_pxethief_pr_11_and_never_falls_back_to_default_branch():
    installer = Path(__file__).resolve().parents[1].joinpath("install.sh").read_text(encoding="utf-8")

    assert "https://github.com/MWR-CyberSec/PXEThief.git" in installer
    assert "fetch origin pull/11/head" in installer
    assert "checkout -B pr-11 FETCH_HEAD" in installer
    assert 'checkout main' not in installer and 'checkout master' not in installer
    assert "CinderPath" not in installer and "ad-enum-sccm-pxe" not in installer


def _init_pinned_checkout(root):
    def git(*args):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    root.mkdir(parents=True, exist_ok=True)
    git("init", "-q")
    git("config", "user.email", "fixture@example.test")
    git("config", "user.name", "fixture")
    (root / "pxethief.py").write_text("# fixture\n")
    git("add", "-A")
    git("commit", "-qm", "base")
    git("checkout", "-qb", "pr-11")
    (root / "pr11.txt").write_text("pinned\n")
    git("add", "-A")
    git("commit", "-qm", "pr-11")
    (root / ".venv" / "bin").mkdir(parents=True)
    interpreter = root / ".venv" / "bin" / "python3"
    interpreter.write_text("#!/bin/sh\nexit 0\n")
    interpreter.chmod(0o755)


def test_capability_recognizes_a_healthy_pinned_installation(tmp_path, monkeypatch):
    root = tmp_path / "PXEThief"
    _init_pinned_checkout(root)
    monkeypatch.setenv("PXETHIEF_ROOT", str(root))

    capability = px.pxethief_capability()
    assert capability["status"] == "PASS" and capability["commit"]


def test_capability_rejects_a_checkout_that_is_not_on_pr_11(tmp_path, monkeypatch):
    root = tmp_path / "PXEThief"
    _init_pinned_checkout(root)
    subprocess.run(["git", "checkout", "-q", "-"], cwd=root, check=True, capture_output=True)
    monkeypatch.setenv("PXETHIEF_ROOT", str(root))

    capability = px.pxethief_capability()
    assert capability["status"] == "FAILED" and "pr-11" in capability["detail"]


def test_capability_check_is_installation_only_and_never_gates_on_privilege(tmp_path, monkeypatch):
    # The check verifies checkout/interpreter/imports; it must not claim that
    # raw-socket privilege is a precondition (that is the tool's runtime answer).
    root = tmp_path / "PXEThief"
    _init_pinned_checkout(root)
    monkeypatch.setenv("PXETHIEF_ROOT", str(root))

    capability = px.pxethief_capability()

    assert capability["status"] == "PASS"
    assert "cap_net" not in capability["detail"].lower()
    assert "root" not in capability["detail"].lower()


def test_pxe_candidates_only_uses_discovered_dp_and_mp_and_is_deterministic():
    result = {
        "distribution_points": [],
        "management_points": [
            {"fqdn": "MECM.sccm.lab", "ip_addresses": ["10.1.10.41"], "site_code": "P01"},
            {"host": "MECM.sccm.lab", "ip_addresses": ["10.1.10.41"], "site_code": "P01"},
        ],
    }
    assert pxe_candidates(result) == [{"dp": "10.1.10.41", "host": "MECM.sccm.lab",
                                       "site_code": "P01", "basis": "management-point",
                                       "pxe_evidence": False}]
    assert pxe_candidates({"hosts": [{"fqdn": "unrelated.sccm.lab"}]}) == []


def test_normalized_pxe_validation_never_carries_raw_tool_text():
    normalized = normalize_pxe_validation({"dp": "192.0.2.41", "state": "not tested",
                                           "errors": ["reason"], "stdout": "raw"})
    assert normalized["state"] == "NOT TESTED" and normalized["recovered_count"] == 0
    assert "stdout" not in normalized and "raw" not in json.dumps(normalized)
