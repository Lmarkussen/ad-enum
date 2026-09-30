"""Startup warning when PXEThief lacks raw-socket privilege (advisory only)."""
import sys
from pathlib import Path

from ad_enum import cli
from ad_enum import pxethief_adapter as px
from test_pipeline_smoke import FakeCollector

SCANNER_SECRET = "ScannerOnlySecret"
WARNING_TEXT = "PXEThief requires root or CAP_NET_RAW"


# --- capability detection --------------------------------------------------

def test_root_is_recognized_as_privileged(monkeypatch):
    monkeypatch.setattr(px, "_effective_uid", lambda: 0)
    assert px.has_raw_socket_privilege(status_text="CapEff:\t0000000000000000\n") is True


def test_effective_cap_net_raw_without_root_is_privileged(monkeypatch):
    monkeypatch.setattr(px, "_effective_uid", lambda: 1000)
    # bit 13 (CAP_NET_RAW) set -> 0x2000
    assert px.has_raw_socket_privilege(status_text="Name:\tpython\nCapEff:\t0000000000002000\n") is True


def test_non_root_without_cap_net_raw_is_not_privileged(monkeypatch):
    monkeypatch.setattr(px, "_effective_uid", lambda: 1000)
    for text in ("CapEff:\t0000000000000000\n",
                 "CapEff:\t0000000000001000\n",   # bit 12, not CAP_NET_RAW
                 "Name:\tpython\n"):               # no CapEff line at all
        assert px.has_raw_socket_privilege(status_text=text) is False


def test_malformed_capability_source_fails_safe(monkeypatch):
    monkeypatch.setattr(px, "_effective_uid", lambda: 1000)
    for text in ("CapEff:\tnot-hex\n", "CapEff:\n", "", None):
        if text is None:
            continue
        assert px.has_raw_socket_privilege(status_text=text) is False


def test_unavailable_proc_status_fails_safe(monkeypatch):
    monkeypatch.setattr(px, "_effective_uid", lambda: 1000)
    monkeypatch.setattr(px, "PROC_SELF_STATUS", "/nonexistent/adenum/proc-self-status")
    assert px.has_raw_socket_privilege() is False


def test_runtime_permission_error_normalization_is_unchanged():
    result = px.parse_pxethief_output("PermissionError: [Errno 1] Operation not permitted\n")
    assert result["state"] == "NOT TESTED"
    reason = result["errors"][0]
    assert "raw-socket privilege (root or CAP_NET_RAW)" in reason
    assert "CAP_NET_ADMIN" not in reason


# --- CLI startup warning ---------------------------------------------------

def _sccm(entries):
    return {"hosts": [], "management_points": [], "distribution_points": list(entries),
            "site_servers": [], "sms_providers": [], "sql_servers": [], "sup_wsus": [],
            "pxe": {"status": "UNKNOWN"}, "status": "sccm-publication-and-inventory"}


def _configure(monkeypatch, tmp_path, *, endpoints=(), pxe_privilege=False,
               pxe_result=None, modules="all"):
    monkeypatch.setattr(cli, "Collector", FakeCollector)
    monkeypatch.setattr(cli, "has_raw_socket_privilege", lambda *a, **k: pxe_privilege)
    monkeypatch.setattr(cli, "probe_anonymous_ldap",
                        lambda *a, **k: {"bind": "DENIED", "rootdse": "DENIED",
                                         "domain_data": "DENIED", "sources": ["t"]})
    monkeypatch.setattr(cli, "probe_anonymous_smb",
                        lambda *a, **k: {"session": "DENIED", "share_enumeration": "DENIED",
                                         "shares": [], "sources": ["t"]})
    monkeypatch.setattr(cli, "collect_sysvol", lambda *a, **k: {"status": "PASS", "files": []})
    monkeypatch.setattr(cli, "collect_netlogon", lambda *a, **k: {"status": "PASS", "files": []})
    monkeypatch.setattr(cli, "discover_sccm", lambda *a, **k: _sccm(endpoints))
    monkeypatch.setattr(cli, "probe_management_points", lambda *a, **k: [])
    monkeypatch.setattr(cli, "execute_external", lambda *a, **k: ({}, []))
    monkeypatch.setattr(cli, "pxethief_capability", lambda *a, **k: {"status": "PASS", "detail": "x"})
    monkeypatch.setattr(cli, "run_pxethief",
                        lambda *a, **k: pxe_result or px.normalize_pxe_validation(
                            {"dp": "10.1.10.41", "state": "NOT TESTED", "source": "PXEThief",
                             "errors": ["fixture"]}))
    monkeypatch.setattr(cli, "sccmhunter_capability", lambda *a, **k: {"status": "PASS", "detail": "x"})
    monkeypatch.setattr(cli, "run_sccmhunter", lambda *a, **k: {
        "status": "PASS", "source": "SCCMHunter", "command": "fixture", "commit": "",
        "site_codes": ["P01"], "management_points": [], "distribution_points": [],
        "site_servers": []})
    monkeypatch.setattr(cli, "sccmsecrets_capability", lambda *a, **k: {"status": "PASS", "detail": "x"})
    monkeypatch.setattr(cli, "run_sccmsecrets_files", lambda dp, *a, **k: {
        "dp": str(dp), "state": "NOT TESTED", "access": "UNKNOWN", "indexed": 0,
        "downloaded": 0, "interesting": 0, "files": [], "credentials": [],
        "errors": ["fixture"], "source": "", "command": ""})
    monkeypatch.setattr(sys, "argv", ["ad-enum.py", "-u", "svc-scan", "-p", SCANNER_SECRET,
                                      "-domain", "sccm.lab", "-dc-ip", "10.1.10.40",
                                      "--modules", modules, "--output-dir", str(tmp_path),
                                      "--no-color"])


def test_unprivileged_scan_warns_once_and_still_completes(monkeypatch, tmp_path, capsys):
    _configure(monkeypatch, tmp_path, pxe_privilege=False)

    assert cli.main() == 0
    out = capsys.readouterr().out

    assert out.count(WARNING_TEXT) == 1
    assert "Other checks will continue normally." in out
    assert "Credentials are Valid" in out
    assert "\033[" not in out  # --no-color
    assert SCANNER_SECRET not in out
    # The scan is not aborted: the final report and workspace are written.
    assert (tmp_path / "sccm.lab" / "results.txt").is_file()
    assert '"status": "COMPLETE"' in (tmp_path / "sccm.lab" / "scan.json").read_text()


def test_privileged_scan_does_not_warn(monkeypatch, tmp_path, capsys):
    _configure(monkeypatch, tmp_path, pxe_privilege=True)

    assert cli.main() == 0
    out = capsys.readouterr().out
    assert WARNING_TEXT not in out


def test_root_run_via_real_capability_helper_does_not_warn(monkeypatch, tmp_path, capsys):
    # Exercise the real helper through the CLI: euid 0 must suppress the warning.
    _configure(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "has_raw_socket_privilege", px.has_raw_socket_privilege)
    monkeypatch.setattr(px, "_effective_uid", lambda: 0)

    assert cli.main() == 0
    assert WARNING_TEXT not in capsys.readouterr().out


def test_effective_cap_net_raw_run_does_not_warn(monkeypatch, tmp_path, capsys):
    _configure(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "has_raw_socket_privilege", px.has_raw_socket_privilege)
    monkeypatch.setattr(px, "_effective_uid", lambda: 1000)
    status = tmp_path / "proc-self-status"
    status.write_text("Name:\tpython\nCapEff:\t0000000000002000\n", encoding="utf-8")
    monkeypatch.setattr(px, "PROC_SELF_STATUS", str(status))

    assert cli.main() == 0
    assert WARNING_TEXT not in capsys.readouterr().out


def test_warning_is_advisory_and_does_not_gate_pxethief(monkeypatch, tmp_path, capsys):
    # Even when the startup warning fires, PXEThief is still invoked per the
    # existing pipeline and the runtime NOT TESTED reason remains authoritative.
    calls = []

    def fake_run(target, *a, **k):
        calls.append(target)
        return px.normalize_pxe_validation({
            "dp": str(target), "state": "NOT TESTED", "source": "PXEThief",
            "errors": ["PXEThief requires raw-socket privilege (root or CAP_NET_RAW) "
                       "to send the PXE request"]})

    _configure(monkeypatch, tmp_path, endpoints=[
        {"fqdn": "mecm.sccm.lab", "ip_addresses": ["10.1.10.41"], "site_code": "P01"}],
        pxe_privilege=False)
    monkeypatch.setattr(cli, "run_pxethief", fake_run)

    assert cli.main() == 0
    assert calls == ["10.1.10.41"]
    out = capsys.readouterr().out
    assert WARNING_TEXT in out
    results = (tmp_path / "sccm.lab" / "results.txt").read_text()
    assert "raw-socket privilege (root or CAP_NET_RAW)" in results
