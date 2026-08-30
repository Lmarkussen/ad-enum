import sys
import types

from ad_enum.adapters.base import ToolAdapter
from ad_enum.anonymous import probe_anonymous_ldap, probe_anonymous_smb


def test_external_output_can_stream_both_channels_without_losing_capture(tmp_path):
    script = tmp_path / "collector.py"
    script.write_text("import sys; print('target evidence'); print('diagnostic', file=sys.stderr)")
    seen = []
    result = ToolAdapter().execute([sys.executable, str(script)], timeout=3,
                                   secrets=("operational-secret",),
                                   stream=lambda channel, line: seen.append((channel, line.rstrip())))
    assert result.returncode == 0
    assert result.stdout == "target evidence\n"
    assert result.stderr == "diagnostic\n"
    assert set(seen) == {("stdout", "target evidence"), ("stderr", "diagnostic")}


def test_external_output_stream_redacts_only_operational_secret(tmp_path):
    script = tmp_path / "collector.py"
    script.write_text("print('operational-secret')")
    seen = []
    ToolAdapter().execute([sys.executable, str(script)], timeout=3,
                          secrets=("operational-secret",),
                          stream=lambda channel, line: seen.append(line))
    assert seen == ["<redacted>\n"]


def test_anonymous_ldap_distinguishes_rootdse_from_domain_data(monkeypatch):
    class FakeServer:
        def __init__(self, *args, **kwargs): pass
    class FakeEntry:
        entry_attributes_as_dict = {"defaultNamingContext": ["DC=sccm,DC=lab"]}
    class FakeConnection:
        entries = [FakeEntry()]
        def __init__(self, *args, **kwargs): pass
        def search(self, base, *args, **kwargs): return base == ""
        def unbind(self): pass
    monkeypatch.setattr("ad_enum.anonymous.Server", FakeServer)
    monkeypatch.setattr("ad_enum.anonymous.Connection", FakeConnection)
    result = probe_anonymous_ldap("dc.sccm.lab", "sccm.lab")
    assert result["bind"] == "ACCEPTED"
    assert result["rootdse"] == "READABLE"
    assert result["domain_data"] == "DENIED"


def test_anonymous_ldap_reports_domain_data_when_bounded_query_returns_entries(monkeypatch):
    class FakeServer:
        def __init__(self, *args, **kwargs): pass
    class FakeEntry:
        entry_attributes_as_dict = {"defaultNamingContext": ["DC=sccm,DC=lab"]}
    class FakeConnection:
        entries = [FakeEntry()]
        def __init__(self, *args, **kwargs): pass
        def search(self, base, *args, **kwargs): return True
        def unbind(self): pass
    monkeypatch.setattr("ad_enum.anonymous.Server", FakeServer)
    monkeypatch.setattr("ad_enum.anonymous.Connection", FakeConnection)
    result = probe_anonymous_ldap("dc.sccm.lab", "sccm.lab")
    assert result["domain_data"] == "READABLE"
    assert result["sample_count"] == 1


def test_anonymous_smb_does_not_equate_session_with_share_enumeration(monkeypatch):
    class FakeSMB:
        def __init__(self, *args, **kwargs): pass
        def login(self, *args): pass
        def listShares(self): raise RuntimeError("denied")
        def logoff(self): pass
    monkeypatch.setitem(sys.modules, "impacket", types.ModuleType("impacket"))
    smb = types.ModuleType("impacket.smbconnection"); smb.SMBConnection = FakeSMB
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", smb)
    result = probe_anonymous_smb("file01.sccm.lab", "10.1.10.50")
    assert result["session"] == "SESSION_ACCEPTED"
    assert result["share_enumeration"] == "DENIED"
    assert result["shares"] == []


def test_anonymous_smb_normalizes_share_names(monkeypatch):
    class FakeShare:
        def __getitem__(self, key): return "Public\x00"
    class FakeSMB:
        def __init__(self, *args, **kwargs): pass
        def login(self, *args): pass
        def listShares(self): return [FakeShare()]
        def logoff(self): pass
    monkeypatch.setitem(sys.modules, "impacket", types.ModuleType("impacket"))
    smb = types.ModuleType("impacket.smbconnection"); smb.SMBConnection = FakeSMB
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", smb)
    result = probe_anonymous_smb("file01.sccm.lab", "10.1.10.50")
    assert result["session"] == "SESSION_ACCEPTED"
    assert result["share_enumeration"] == "SHARE_ENUM_ALLOWED"
    assert result["shares"] == ["Public"]
