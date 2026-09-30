"""Focused tests for the SCCMSecrets Distribution Point inspection adapter."""
import json
import subprocess
from pathlib import Path

from ad_enum import sccmsecrets_adapter as ss


def _build_loot(workdir, *, index_lines=(), files=None):
    loot = Path(workdir) / "loot" / "2026-01-01_00-00-00_files"
    loot.mkdir(parents=True, exist_ok=True)
    (loot / "index.txt").write_text("\n".join(index_lines) + "\n", encoding="utf-8")
    for relative, body in (files or {}).items():
        path = loot / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return loot


_INDEX = (
    "\u2514\u2500\u2500 P0100001.1/",
    "    \u251c\u2500\u2500 http://dp01.example.local/sms_dp_smspkg$/P0100001.1/i386/",
    "    \u2502   \u251c\u2500\u2500 http://dp01.example.local/sms_dp_smspkg$/P0100001.1/i386/client.msi",
    "    \u2514\u2500\u2500 http://dp01.example.local/sms_dp_smspkg$/P0100001.1/Join.ps1",
)


def test_parse_authenticated_dp_with_interesting_file(tmp_path):
    workdir = tmp_path / "work"
    _build_loot(workdir, index_lines=_INDEX, files={
        "packages/P0100001.1/Join.ps1":
            "New-ADUser -Name svc-naa\n"
            "   $password = 'ExampleOnly-Secret'\n",
        "packages/P0100001.1/client.msi": "binary",
    })
    stdout = (" - Anonymous Distribution Point access : [NOT VULNERABLE] "
              "(distribution point does not allow anonymous access)\n[+] All done. Bye!")

    result = ss.parse_files_artifacts(workdir, stdout)

    assert result["state"] == "ACCESSIBLE" and result["access"] == "AUTHENTICATED"
    assert result["indexed"] == 2 and result["downloaded"] == 2
    assert result["interesting"] == 1 and len(result["credentials"]) == 1
    assert result["credentials"][0]["value"] == "ExampleOnly-Secret"
    assert result["credentials"][0]["source"] == "SCCMSecrets"
    assert result["loot"] == "2026-01-01_00-00-00_files"


def test_parse_anonymous_dp_is_reported_as_anonymous(tmp_path):
    workdir = tmp_path / "work"
    _build_loot(workdir, index_lines=_INDEX)
    stdout = (" - Anonymous Distribution Point access : [VULNERABLE] "
              "Distribution point allows anonymous access")

    result = ss.parse_files_artifacts(workdir, stdout)
    assert result["access"] == "ANONYMOUS" and result["state"] == "ACCESSIBLE"


def test_parse_inaccessible_dp_reports_not_accessible(tmp_path):
    stdout = (" - Anonymous Distribution Point access : [NOT VULNERABLE] "
              "(distribution point does not allow anonymous access)\n"
              "[-] It seems like provided credentials do not allow to successfully "
              "authenticate to the distribution point.")

    result = ss.parse_files_artifacts(tmp_path / "work", stdout)
    assert result["state"] == "NOT ACCESSIBLE" and result["errors"]
    assert result["indexed"] == 0 and result["credentials"] == []


def test_parse_empty_index_is_accessible_with_zero_indexed(tmp_path):
    workdir = tmp_path / "work"
    _build_loot(workdir, index_lines=())
    result = ss.parse_files_artifacts(workdir, " - Anonymous Distribution Point access : [NOT VULNERABLE]")
    assert result["state"] == "ACCESSIBLE" and result["indexed"] == 0


def _fake_checkout(tmp_path, monkeypatch, script_body):
    root = tmp_path / "SCCMSecrets"
    (root / ".venv" / "bin").mkdir(parents=True)
    interpreter = root / ".venv" / "bin" / "python3"
    interpreter.write_text("#!/bin/sh\nexec python3 \"$@\"\n")
    interpreter.chmod(0o755)
    (root / "SCCMSecrets.py").write_text(script_body)
    monkeypatch.setenv("SCCMSECRETS_ROOT", str(root))
    return root


_WRITES_LOOT = """
import os, sys
os.makedirs("loot/2026-01-01_00-00-00_files/packages/P0100001.1", exist_ok=True)
open("loot/2026-01-01_00-00-00_files/index.txt", "w").write("x\\n")
open("loot/2026-01-01_00-00-00_files/packages/P0100001.1/Join.ps1", "w").write(
    "password = 'ExampleOnly-Secret'\\n")
print(" - Anonymous Distribution Point access : [NOT VULNERABLE]")
print("[-] It seems like provided credentials do not allow to successfully authenticate; attempted password/hash: '"
      + sys.argv[sys.argv.index("-p") + 1] + "'")
"""


def test_run_files_isolates_artifacts_and_never_persists_the_scanner_password(tmp_path, monkeypatch):
    _fake_checkout(tmp_path, monkeypatch, _WRITES_LOOT)
    workdir = tmp_path / "raw" / "dp01"

    result = ss.run_files("dp01.example.local", "localuser", "ScannerOnlySecret",
                          timeout=60, workdir=workdir)

    assert result["state"] == "ACCESSIBLE" and result["dp"] == "dp01.example.local"
    assert result["access"] == "AUTHENTICATED"
    assert (workdir / "loot").is_dir() and result["indexed"] == 1
    assert "ScannerOnlySecret" not in (workdir / "stdout.txt").read_text()
    assert "<redacted>" in (workdir / "stdout.txt").read_text()
    assert "ScannerOnlySecret" not in result["command"] and "<password>" in result["command"]
    assert "ScannerOnlySecret" not in json.dumps(result)


def test_run_files_reports_unavailable_tool_without_fabricating_state(tmp_path, monkeypatch):
    monkeypatch.setenv("SCCMSECRETS_ROOT", str(tmp_path / "missing"))
    result = ss.run_files("dp01.example.local", "localuser", "ScannerOnlySecret",
                          timeout=5, workdir=tmp_path / "raw")
    assert result["state"] == "NOT TESTED" and result["source"] == ""
    assert result["indexed"] == 0


_LOGS_TO_STDERR = """
import os, sys
os.makedirs("loot/2026-01-01_00-00-00_files", exist_ok=True)
open("loot/2026-01-01_00-00-00_files/index.txt", "w").write("x\\n")
sys.stderr.write(" - Anonymous Distribution Point access : [NOT VULNERABLE] "
                 "(distribution point does not allow anonymous access)\\n")
print("[+] All done. Bye!")
"""


def test_run_files_reads_context_markers_from_stderr(tmp_path, monkeypatch):
    # SCCMSecrets logs its context lines through ``logging`` (stderr), while
    # progress goes to stdout; both must feed the normalizer.
    _fake_checkout(tmp_path, monkeypatch, _LOGS_TO_STDERR)
    result = ss.run_files("dp01.example.local", "localuser", "ScannerOnlySecret",
                          timeout=60, workdir=tmp_path / "raw")
    assert result["access"] == "AUTHENTICATED" and result["state"] == "ACCESSIBLE"


def test_capability_reports_missing_and_healthy_checkout(tmp_path, monkeypatch):
    monkeypatch.setenv("SCCMSECRETS_ROOT", str(tmp_path / "missing"))
    assert ss.sccmsecrets_capability()["status"] == "NOT AVAILABLE"

    root = _fake_checkout(tmp_path, monkeypatch, "print('help')\n")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True, capture_output=True)
    assert ss.sccmsecrets_capability()["status"] == "PASS"


def test_installer_provisions_isolated_sccmsecrets_from_public_source():
    installer = Path(__file__).resolve().parents[1].joinpath("install.sh").read_text(encoding="utf-8")
    assert "https://github.com/synacktiv/SCCMSecrets.git" in installer
    assert ".cache/SCCMSecrets" in installer
    assert "sccmsecrets_root/.venv" in installer
    assert "SCCMSecrets.py --help" in installer
    assert "SCCMSecrets.py policies" not in installer
