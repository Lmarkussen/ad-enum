from ad_enum.access import (from_netexec_hosts, merge_access, normalize_access,
                            parse_netexec_auth, filter_redundant_access_targets)
from ad_enum.adapters.netexec import NetExecAdapter
from types import SimpleNamespace


def test_access_separates_authentication_from_privilege():
    records = from_netexec_hosts([
        {"host": "DC.example", "ip": "10.0.0.1", "smb_authenticated": True},
        {"host": "MECM.example", "ip": "10.0.0.2", "smb_authenticated": False},
    ], "user")
    assert records[0]["authentication"] == "AUTHENTICATED"
    assert records[0]["privilege"] == "UNKNOWN"
    assert records[1]["authentication"] == "DENIED"


def test_access_deduplicates_and_prefers_success():
    result = merge_access([
        {"host": "dc", "protocol": "SMB", "port": 445, "authentication": "denied"},
        {"host": "DC", "protocol": "smb", "port": 445, "authentication": "success"},
    ])
    assert len(result) == 1
    assert result[0]["authentication"] == "AUTHENTICATED"


def test_access_deduplicates_short_and_fqdn_names_by_ip():
    result = merge_access([
        {"host": "DC", "ip": "10.0.0.1", "protocol": "SMB", "port": 445,
         "authentication": "authenticated", "privilege": "unknown"},
        {"host": "DC.example", "ip": "10.0.0.1", "protocol": "SMB", "port": 445,
         "authentication": "authenticated", "privilege": "admin"},
    ])
    assert len(result) == 1
    assert result[0]["host"] == "DC.example"
    assert result[0]["privilege"] == "ADMIN"


def test_access_skips_auth_targets_already_proven_by_collectors():
    targets = [
        {"ip": "10.0.0.1", "service": "SMB", "state": "OPEN"},
        {"ip": "10.0.0.1", "service": "LDAP", "state": "OPEN"},
        {"ip": "10.0.0.1", "service": "WinRM", "state": "OPEN"},
    ]
    existing = [
        {"ip": "10.0.0.1", "protocol": "SMB", "authentication": "AUTHENTICATED"},
        {"ip": "10.0.0.1", "protocol": "LDAP", "authentication": "AUTHENTICATED"},
    ]
    remaining = filter_redundant_access_targets(targets, existing)
    assert [item["service"] for item in remaining] == ["WinRM"]


def test_access_rejects_unknown_privilege_labels():
    assert normalize_access({"authentication": "success", "privilege": "root"})["privilege"] == "UNKNOWN"


def test_netexec_auth_parser_requires_explicit_marker():
    result = parse_netexec_auth("SMB 10.0.0.1 445 TCP OPEN", protocol="SMB",
                                host="dc.example", principal="user")
    assert result["authentication"] == "UNKNOWN"
    result = parse_netexec_auth("SMB 10.0.0.1 445 [+] DOMAIN\\user (Pwn3d!)",
                                protocol="SMB", host="dc.example", principal="user")
    assert result["authentication"] == "AUTHENTICATED"
    assert result["privilege"] == "ADMIN"


def test_netexec_access_command_has_no_post_auth_actions():
    command = NetExecAdapter().build_access_command(
        protocol="ssh", username="user", password="scanner-secret", target="10.0.0.5",
        help_text="--no-progress --no-bruteforce")
    assert command[:3] == ["nxc", "ssh", "10.0.0.5"]
    assert "--no-progress" in command
    assert "--no-bruteforce" in command
    assert not any(x in command for x in ("-x", "--exec-method", "--command", "--shell"))


def test_netexec_access_command_preserves_nondefault_port():
    command = NetExecAdapter().build_access_command(
        protocol="mssql", username="user", password="secret", target="10.0.0.5",
        port=1444, help_text="--port PORT")
    assert command[-2:] == ["--port", "1444"]


def test_netexec_access_uses_service_label_when_protocol_is_transport(tmp_path, monkeypatch):
    adapter = NetExecAdapter()
    calls = []
    monkeypatch.setattr(adapter, "resolve_executable", lambda: "/usr/bin/nxc")
    monkeypatch.setattr(adapter, "access_help", lambda protocol: "--no-progress --no-bruteforce")

    def execute(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(stdout="WINRM target 5985 [+] user", stderr="", returncode=0)

    monkeypatch.setattr(adapter, "execute", execute)
    context = SimpleNamespace(
        auth=SimpleNamespace(username="user", password="secret"), domain="example",
        force_kerb=False, timeout=5, workspace=SimpleNamespace(raw_dir=lambda _: tmp_path),
        tool_output_callback=None)
    records = adapter.run_access_checks(context=context, targets=[
        {"host": "server.example", "ip": "10.0.0.5", "protocol": "tcp",
         "service": "WinRM HTTP", "port": 5985}
    ])
    assert calls and calls[0][1:3] == ["winrm", "10.0.0.5"]
    assert records[0]["protocol"] == "WINRM"


def test_netexec_access_skips_closed_service_observations(tmp_path, monkeypatch):
    adapter = NetExecAdapter()
    calls = []
    monkeypatch.setattr(adapter, "resolve_executable", lambda: "/usr/bin/nxc")
    monkeypatch.setattr(adapter, "access_help", lambda protocol: "--no-progress")
    monkeypatch.setattr(adapter, "execute", lambda command, **kwargs: calls.append(command))
    context = SimpleNamespace(
        auth=SimpleNamespace(username="user", password="secret"), domain="example",
        force_kerb=False, timeout=5, workspace=SimpleNamespace(raw_dir=lambda _: tmp_path),
        tool_output_callback=None)
    records = adapter.run_access_checks(context=context, targets=[
        {"host": "server.example", "ip": "10.0.0.5", "protocol": "tcp",
         "service": "SSH", "port": 22, "state": "CLOSED"}
    ])
    assert records == []
    assert calls == []
