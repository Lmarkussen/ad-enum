from types import SimpleNamespace

from ad_enum.core.kerberos_errors import format_skew, translate_kerberos_error
from ad_enum.core import autoconfig


def test_skew_is_human_and_actionable():
    assert format_skew(42) == "42s"
    assert format_skew(252) == "4m 12s"
    assert format_skew(21599) == "~6h"
    failure = translate_kerberos_error("KRB_AP_ERR_SKEW: Clock skew too great")
    assert failure.category == "clock-skew"
    assert "--sync-time" in failure.hint


def test_common_kerberos_error_categories():
    assert translate_kerberos_error("Cannot contact any KDC").category == "kdc-unreachable"
    assert translate_kerberos_error("Client not found in Kerberos database").category == "principal-or-realm"
    assert translate_kerberos_error("Preauthentication failed").category == "bad-credentials"
    assert translate_kerberos_error("server not found in kerberos database").category == "principal-or-realm"


def test_measure_skew_does_not_modify_system(monkeypatch):
    monkeypatch.setattr(autoconfig.shutil, "which", lambda name: "/usr/bin/ntpdate")
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="server 10.0.0.1, stratum 3, offset 21599.6 sec", stderr="")

    result = autoconfig.measure_time_skew("10.0.0.1", runner=runner)
    assert result["status"] == "MEASURED"
    assert result["skew_seconds"] == 21599.6
    assert calls == [["/usr/bin/ntpdate", "-q", "10.0.0.1"]]


def test_measure_skew_parses_ntpdate_compact_format(monkeypatch):
    monkeypatch.setattr(autoconfig.shutil, "which", lambda name: "/usr/bin/ntpdate")
    result = autoconfig.measure_time_skew(
        "10.0.0.1",
        runner=lambda *a, **k: SimpleNamespace(
            returncode=0, stdout="2026-08-30 18:45:24 (+0000) -0.000078 +/- 0.000617 10.0.0.1 s1", stderr=""
        ),
    )
    assert result["status"] == "MEASURED"
    assert result["skew_seconds"] == -0.000078


def test_sync_time_uses_privileged_one_shot_command(monkeypatch):
    monkeypatch.setattr(autoconfig.shutil, "which", lambda name: "/usr/bin/ntpdate")
    monkeypatch.setattr(autoconfig.os, "geteuid", lambda: 1000)
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    result = autoconfig.sync_time("10.0.0.1", runner=runner)
    assert result["status"] == "SYNCED"
    assert calls == [["sudo", "-n", "/usr/bin/ntpdate", "-u", "10.0.0.1"]]
