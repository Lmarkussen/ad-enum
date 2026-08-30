import json
import stat

from ad_enum.cinderpath_adapter import cinderpath_path, run_cinderpath_cred1


def _fake_cinderpath(path, payload):
    path.write_text("#!/bin/sh\n" +
                    "case \"$*\" in *'assess CRED-1 --help'*) printf '%s\\n' 'CRED-1 --format json';; *) printf '%s\\n' '" +
                    json.dumps(payload).replace("'", "'\\\''") + "';; esac\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def test_cinderpath_adapter_normalizes_and_deduplicates_secrets(tmp_path):
    tool = tmp_path / "cinderpath"
    _fake_cinderpath(tool, {"dp": "10.1.10.41", "site": "P01", "interface": "eth0",
                             "task_sequence_policies": 5,
                             "recovered_secrets": [
                                 {"name": "NAA", "type": "task_sequence_variable", "value": "synthetic"},
                                 {"name": "NAA", "type": "task_sequence_variable", "value": "synthetic"}]})
    result = run_cinderpath_cred1("10.1.10.41", executable=str(tool))
    assert result["status"] == "CONFIRMED"
    assert len(result["credentials"]) == 1
    assert result["site_code"] == "P01"


def test_cinderpath_adapter_missing_tool_is_explicit(tmp_path):
    result = run_cinderpath_cred1("10.1.10.41", executable=str(tmp_path / "missing"))
    assert result["status"] == "TOOL FAILURE"
    assert "FileNotFoundError" in result["errors"][0]


def test_cinderpath_capability_accepts_help_without_echoing_technique(tmp_path):
    from ad_enum.cinderpath_adapter import cinderpath_capability

    tool = tmp_path / "cinderpath"
    tool.write_text("#!/bin/sh\nprintf '%s\\n' 'Usage: cinderpath assess' '      --format string'\n",
                    encoding="utf-8")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    assert cinderpath_capability(str(tool))["status"] == "READY"


def test_cinderpath_path_finds_repository_virtualenv_binary(tmp_path, monkeypatch):
    binary = tmp_path / ".venv" / "bin" / "cinderpath"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CINDERPATH_BIN", raising=False)
    monkeypatch.setattr("ad_enum.cinderpath_adapter.shutil.which", lambda _: None)
    assert cinderpath_path() == str(binary)
