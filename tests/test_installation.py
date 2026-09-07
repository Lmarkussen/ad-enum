"""Installer contracts; no package-manager mutation or live network scans."""
from pathlib import Path
import subprocess
import py_compile

import pytest

from ad_enum import doctor
from ad_enum.core import planner
from ad_enum.adapters.networkhound import NetworkHoundAdapter
from ad_enum.adapters.relayking import RelayKingAdapter

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = (ROOT / "install.sh").read_text()
FUNCTIONS = INSTALLER.split('\ndetect_platform\n', 1)[0]


def shell(tmp_path, body):
    script = tmp_path / "installer-test.sh"
    script.write_text(FUNCTIONS + '\n' + body)
    return subprocess.run(["bash", str(script)], text=True, capture_output=True)


@pytest.mark.parametrize("command,adapter", [("NetworkHound.py", NetworkHoundAdapter),
                                             ("relayking.py", RelayKingAdapter)])
def test_repo_tools_resolve_without_path_or_activation(tmp_path, monkeypatch, command, adapter):
    monkeypatch.setattr(planner, "__file__", str(tmp_path / "ad_enum/core/planner.py"))
    monkeypatch.setattr(planner.shutil, "which", lambda _: "/old/tool")
    binary = tmp_path / ".venv/bin" / command
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    monkeypatch.chdir(tmp_path.parent)
    assert planner.find_executable(command) == str(binary)
    assert adapter().resolve_executable() == str(binary)


@pytest.mark.parametrize("command", ["NetworkHound.py", "relayking.py"])
@pytest.mark.parametrize("body,status", [("exit 0", "PASS"), ("exit 7", "FAILED")])
def test_doctor_checks_startup(tmp_path, monkeypatch, command, body, status):
    binary = tmp_path / command
    binary.write_text("#!/bin/sh\n" + body + "\n")
    binary.chmod(0o755)
    monkeypatch.setattr(doctor, "find_executable", lambda _: str(binary))
    assert doctor._tool(command)[0] == status
    binary.chmod(0o644)
    assert doctor._tool(command)[0] == "FAILED"


def test_doctor_checks_required_options_and_timeout(monkeypatch):
    monkeypatch.setattr(doctor, "find_executable", lambda _: "/tool")
    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, "usage", ""))
    assert doctor._tool("relayking.py", required_flags=("--audit",))[0] == "FAILED"
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
    monkeypatch.setattr(doctor.subprocess, "run", timeout)
    assert doctor._tool("NetworkHound.py")[0] == "FAILED"


@pytest.mark.parametrize("missing", [None, "NetworkHound.py", "relayking.py", "cinderpath"])
def test_doctor_required_visibility_and_exit(monkeypatch, capsys, missing):
    monkeypatch.setattr(doctor, "find_executable", lambda name: None if name == missing else "/tool")
    monkeypatch.setattr(doctor.importlib.util, "find_spec", lambda _: True)
    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a, 0, " ".join(flag for _, _, _, flags in doctor.REQUIRED_TOOLS for flag in flags), ""))
    assert doctor.report() == (1 if missing else 0)
    output = capsys.readouterr().out
    assert "NetworkHound" in output and "RelayKing" in output and "CinderPath" in output
    if missing:
        assert "NOT AVAILABLE" in output and "default installation is incomplete" in output


@pytest.mark.parametrize("label,command", [("NetworkHound", "NetworkHound.py"),
                                           ("RelayKing-Depth", "relayking.py")])
def test_script_install_twice_and_failed_startup(tmp_path, label, command):
    # Local upstream fixture exercises real clone, venv, pip and launcher behavior.
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    (upstream / command).write_text('import sys\nif __name__ == "__main__":\n    assert sys.argv[1:] == ["--help"]\nprint("fixture help")\n')
    (upstream / "requirements.txt").write_text("")
    subprocess.run(["git", "init", str(upstream)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(upstream), "add", "."], check=True)
    subprocess.run(["git", "-C", str(upstream), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                    "commit", "-m", "fixture"], check=True, capture_output=True)
    revision = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    body = f'''PYTHON_BIN=python3
mkdir -p "$repo_dir/.venv/bin"
install_script_tool {label} "$repo_dir/upstream" {revision} {command}
'''
    for _ in range(2):
        result = shell(tmp_path, body)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "fixture help" in result.stdout
        py_compile.compile(str(tmp_path / ".venv/bin" / command), doraise=True)
    script = tmp_path / ".cache" / label / command
    script.write_text("raise RuntimeError('broken required tool')\n")
    result = shell(tmp_path, body + 'ok "Installation complete"\n')
    assert result.returncode != 0
    assert "Installation complete" not in result.stdout
    assert f"Checking {label} startup failed" in result.stderr
    assert "Installer log retained at" in result.stdout


@pytest.mark.parametrize("family,expected,forbidden", [
    ("arch", "pacman -S --needed --noconfirm", "apt-get"),
    ("debian", "apt-get install -y", "pacman")])
def test_package_manager_boundaries(tmp_path, family, expected, forbidden):
    result = shell(tmp_path, f'''DISTRO_FAMILY={family}
package_manager_available() {{ return 0; }}
run_logged() {{ shift; printf '%s ' "$@"; printf '\\n'; }}
system_packages=()
for package in python3 python3-dev python3-venv libkrb5-dev golang-go libpcap-dev git build-essential dnsutils rustc cargo; do
  add_system_package "$package"
done
install_system_packages
''')
    assert result.returncode == 0, result.stderr
    assert expected in result.stdout
    assert forbidden not in result.stdout
    assert "pacman -Sy " not in result.stdout
    if family == "arch":
        assert "base-devel bind" in result.stdout and "libpcap" in result.stdout
        assert "python3" not in result.stdout
    else:
        assert "build-essential dnsutils" in result.stdout and "libpcap-dev" in result.stdout


def test_default_install_contains_required_public_sources_and_doctor_gate():
    assert "https://github.com/MorDavid/NetworkHound.git" in INSTALLER
    assert "https://github.com/depthsecurity/RelayKing-Depth.git" in INSTALLER
    assert "https://github.com/Lmarkussen/CinderPath.git" in INSTALLER
    assert 'PIPX_BIN_DIR="$repo_dir/.venv/bin"' in INSTALLER
    assert "ensurepath" not in INSTALLER and "pipx install --force" not in INSTALLER
    assert 'run_logged "Verifying required scan tools with doctor"' in INSTALLER


def test_relayking_help_exit_one_is_only_accepted_with_clean_complete_help(monkeypatch):
    monkeypatch.setattr(doctor, "find_executable", lambda _: "/relayking.py")
    flags = next(flags for _, command, _, flags in doctor.REQUIRED_TOOLS if command == "relayking.py")
    for output, errors, status in (("usage: " + " ".join(flags), "", "PASS"),
                                   ("usage: --audit", "", "FAILED"),
                                   ("usage: " + " ".join(flags), "Traceback", "FAILED")):
        monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, output, errors))
        assert doctor._tool("relayking.py", required_flags=flags)[0] == status
