"""Regression tests for Domain Controllers that require LDAP signing/integrity."""
import pytest
from ldap3.core.exceptions import (LDAPInvalidCredentialsResult,
                                   LDAPSocketOpenError, LDAPStrongerAuthRequiredResult)

from ad_enum import cli
from ad_enum.ldap_collect import Collector, ProtectedLDAPError

SECRET = "ScannerOnlySecret"


def _stronger_auth_required():
    return LDAPStrongerAuthRequiredResult(
        result=8, description="strongerAuthRequired", dn=None,
        message="The server requires binds to turn on integrity checking if SSL/TLS "
                "are not already active on the connection",
        response_type="bindResponse")


def _invalid_credentials():
    return LDAPInvalidCredentialsResult(result=49, description="invalidCredentials", dn=None,
                                        message="80090308: LdapErr: DSID-0C090447",
                                        response_type="bindResponse")


class _Conn:
    def __init__(self, mode):
        self.mode = mode
        self.bound = True

    def unbind(self):
        self.bound = False


def _instrument(monkeypatch, outcomes):
    """Patch the LDAP transport so each mode returns the requested outcome."""
    seen = []
    monkeypatch.setattr(Collector, "_server", lambda self, **kwargs: {
        "mode": "ldaps" if (kwargs.get("use_ssl") if kwargs.get("use_ssl") is not None
                            else self.use_ssl) else ("starttls" if kwargs.get("tls") is not None
                                                     else "plain")})

    def fake_bind(self, server, *, start_tls=False):
        mode = server["mode"]
        seen.append(mode)
        outcome = outcomes.get(mode, LDAPSocketOpenError("unreachable"))
        if isinstance(outcome, Exception):
            raise outcome
        return _Conn(mode)

    monkeypatch.setattr(Collector, "_ntlm_bind", fake_bind)
    return Collector("192.0.2.10", "svc-scan", SECRET, "example.test"), seen


def test_plain_bind_success_is_used_without_protection(monkeypatch):
    collector, seen = _instrument(monkeypatch, {"plain": "ok"})

    conn, _ = collector._connection()

    assert conn.mode == "plain" and seen == ["plain"]
    assert collector.negotiated_protection is None


def test_stronger_auth_required_falls_back_to_protected_ldap(monkeypatch):
    collector, seen = _instrument(monkeypatch,
                                  {"plain": _stronger_auth_required(), "starttls": "ok"})

    conn, _ = collector._connection()

    assert conn.mode == "starttls"
    assert collector.negotiated_protection == "starttls"
    assert seen == ["plain", "starttls"]


def test_stronger_auth_required_then_starttls_unavailable_uses_ldaps(monkeypatch):
    collector, seen = _instrument(monkeypatch, {
        "plain": _stronger_auth_required(),
        "starttls": LDAPSocketOpenError("starttls refused"),
        "ldaps": "ok"})

    conn, _ = collector._connection()

    assert conn.mode == "ldaps" and seen == ["plain", "starttls", "ldaps"]
    assert collector.negotiated_protection == "ldaps"


def test_protected_bind_rejecting_credentials_reports_invalid(monkeypatch):
    collector, _ = _instrument(monkeypatch, {"plain": _stronger_auth_required(),
                                             "starttls": _invalid_credentials()})

    with pytest.raises(LDAPInvalidCredentialsResult):
        collector._connection()


def test_protected_transport_failure_is_a_security_error_not_invalid(monkeypatch):
    collector, _ = _instrument(monkeypatch, {
        "plain": _stronger_auth_required(),
        "starttls": LDAPSocketOpenError("tls handshake failed"),
        "ldaps": LDAPSocketOpenError("connection reset")})

    with pytest.raises(ProtectedLDAPError) as excinfo:
        collector._connection()

    message = str(excinfo.value)
    assert "protected LDAP connection could not be established" in message
    assert "invalid" not in message.lower()
    assert SECRET not in message


def test_plain_invalid_credentials_is_not_mistaken_for_a_policy_error(monkeypatch):
    collector, seen = _instrument(monkeypatch, {"plain": _invalid_credentials()})

    with pytest.raises(LDAPInvalidCredentialsResult):
        collector._connection()

    assert seen == ["plain"]  # no pointless protected retry for a real auth answer


def test_protected_strategy_is_remembered_for_later_connections(monkeypatch):
    collector, seen = _instrument(monkeypatch,
                                  {"plain": _stronger_auth_required(), "starttls": "ok"})

    collector._connection()
    collector._connection()

    # The rejected insecure track is never retried once protection is required.
    assert seen == ["plain", "starttls", "starttls"]


def test_unexpected_bind_error_is_indeterminate_and_never_leaks_the_secret(monkeypatch):
    collector, _ = _instrument(monkeypatch,
                               {"plain": LDAPSocketOpenError(f"boom {SECRET}")})

    with pytest.raises(LDAPSocketOpenError) as excinfo:
        collector._connection()

    assert SECRET in str(excinfo.value)  # raised as-is; scrubbing happens at the CLI edge


def _cli(monkeypatch, outcome):
    class StubCollector:
        def __init__(self, *args, **kwargs):
            self.negotiated_protection = None
            self.kerberos_session = None

        def preflight(self):
            raise outcome

        def collect(self):
            raise outcome

    monkeypatch.setattr(cli, "Collector", StubCollector)
    monkeypatch.setattr(cli, "probe_anonymous_ldap", lambda *a, **k: {
        "bind": "DENIED", "rootdse": "DENIED", "domain_data": "DENIED", "sources": ["test"]})


def test_cli_never_reports_invalid_credentials_for_a_policy_error(monkeypatch, capsys, tmp_path):
    _cli(monkeypatch, ProtectedLDAPError("DC requires LDAP integrity (starttls: refused)"))
    import sys
    monkeypatch.setattr(sys, "argv", ["ad-enum.py", "-u", "u", "-p", SECRET,
                                      "-domain", "example.test", "-dc-ip", "192.0.2.10",
                                      "--output-dir", str(tmp_path), "--no-color"])

    assert cli.main() == 2
    output = capsys.readouterr().out
    assert "Credentials Invalid" not in output
    assert "LDAP integrity" in output


def test_cli_reports_invalid_credentials_for_a_real_auth_rejection(monkeypatch, capsys, tmp_path):
    _cli(monkeypatch, _invalid_credentials())
    import sys
    monkeypatch.setattr(sys, "argv", ["ad-enum.py", "-u", "u", "-p", SECRET,
                                      "-domain", "example.test", "-dc-ip", "192.0.2.10",
                                      "--output-dir", str(tmp_path), "--no-color"])

    assert cli.main() == 2
    output = capsys.readouterr().out
    assert "Credentials Invalid" in output
    assert SECRET not in output
