import stat

from ad_enum.cred1_adapter import run_safe_cred1


def test_safe_cred1_adapter_passes_only_bounded_safe_arguments(tmp_path):
    helper = tmp_path / "helper"
    helper.write_text("#!/bin/sh\nprintf '%s\\n' '{\"dp\":\"10.0.0.5\",\"pxe\":\"CONFIRMED\",\"tftp\":\"CONFIRMED\",\"media_protection\":\"PROTECTED_OR_ENCRYPTED\"}'\n", encoding="utf-8")
    helper.chmod(helper.stat().st_mode | stat.S_IXUSR)
    result = run_safe_cred1("10.0.0.5", executable=str(helper), timeout=3)
    assert result["pxe"] == "CONFIRMED"
    assert result["media_protection"] == "PROTECTED_OR_ENCRYPTED"


def test_safe_cred1_unavailable_is_explicit_and_nonsecret(tmp_path):
    result = run_safe_cred1("10.0.0.5", executable=str(tmp_path / "missing"))
    assert result["secret_inspection"] == "NOT ATTEMPTED"
    assert any("FileNotFoundError" in item for item in result["evidence"])


def test_install_builds_source_helper_without_binary_vendoring():
    installer = open("install.sh", encoding="utf-8").read()
    assert "go -C helpers/sccm_pxe build -o \"$repo_dir/.venv/bin/ad-enum-sccm-pxe\" ." in installer
    assert "pipx install --force netexec" in installer
