import io
import os
from types import SimpleNamespace
from ad_enum.core.console import Console
from ad_enum.core.kerberos_session import KerberosSession

def test_console_no_color_and_status_rendering():
    stream = io.StringIO()
    c = Console(no_color=True, stream=stream)
    c.heading("Findings"); c.status("Credentials are Valid", "VALID")
    assert "\\033" not in stream.getvalue()
    assert "Findings" in stream.getvalue()

def test_kerberos_session_lifecycle_is_ephemeral(monkeypatch):
    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr("ad_enum.core.kerberos_session.subprocess.run", fake_run)
    session = KerberosSession("user", "secret", "example.test", "dc.example.test")
    previous_cache = os.environ.get("KRB5CCNAME")
    previous_config = os.environ.get("KRB5_CONFIG")
    session.acquire()
    cache, config = session.ccache, session.krb5_config
    assert os.environ["KRB5CCNAME"] == cache
    assert os.environ["KRB5_CONFIG"] == config
    assert session.redacted()["ccache"] == "<ephemeral>"
    session.close()
    assert not os.path.exists(cache)
    assert not os.path.exists(config)
    assert os.environ.get("KRB5CCNAME") == previous_cache
    assert os.environ.get("KRB5_CONFIG") == previous_config
