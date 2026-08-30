from ad_enum.access import from_netexec_hosts, merge_access, normalize_access, parse_netexec_auth
from ad_enum.adapters.netexec import NetExecAdapter


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
