import json
from pathlib import Path
import pytest
from ad_enum.core.workspace import ScanWorkspace, canonical_domain

def test_dns_domain_workspace_is_lowercase(tmp_path):
    ws = ScanWorkspace(tmp_path, "DC=SCCM,DC=LAB", original_target="10.1.10.40", scan_id="one")
    assert ws.root == tmp_path.resolve() / "sccm.lab"
    assert ws.raw_dir("ADCS").name == "raw"

def test_ip_target_uses_discovered_domain(tmp_path):
    ws = ScanWorkspace(tmp_path, "sccm.lab", original_target="10.1.10.40", scan_id="one")
    assert ws.root.name == "sccm.lab"
    assert ws.original_target == "10.1.10.40"

@pytest.mark.parametrize("value", ["../../escape", "/tmp/x", "SCCM LAB"])
def test_workspace_name_cannot_escape(tmp_path, value):
    ws = ScanWorkspace(tmp_path, value, scan_id="one")
    assert ws.root.parent == tmp_path.resolve()
    assert ".." not in ws.root.name

def test_module_paths_and_relative_provenance(tmp_path):
    ws = ScanWorkspace(tmp_path, "local.lab", scan_id="one")
    path = ws.write_json(ws.findings_path("ADCS"), {"artifact": "ok"})
    assert ws.relative(path) == "ADCS/findings.json"
    assert json.loads(path.read_text())["artifact"] == "ok"
    assert not (ws.root / "BloodHound").exists()

def test_module_names_keep_operator_facing_layout(tmp_path):
    ws = ScanWorkspace(tmp_path, "local.lab", scan_id="one")
    assert ws.module_dir("BloodHound").name == "BloodHound"
    assert ws.raw_dir("LDAPDomainDump").parts[-2:] == ("LDAPDomainDump", "raw")

def test_existing_workspace_is_non_destructive(tmp_path):
    root = tmp_path / "sccm.lab"
    root.mkdir(); (root / "operator.txt").write_text("keep")
    ws = ScanWorkspace(tmp_path, "sccm.lab", scan_id="two")
    assert (root / "operator.txt").read_text() == "keep"
    assert ws.history_root.exists()

def test_domain_normalization_rejects_empty():
    with pytest.raises(ValueError): canonical_domain("../..")
    with pytest.raises(ValueError): ScanWorkspace("/tmp", "..", scan_id="one")

def test_invalid_credentials_do_not_create_workspace(tmp_path, monkeypatch, capsys):
    import sys
    import ad_enum.cli as cli
    class BadCollector:
        def __init__(self, *args, **kwargs): pass
        def collect(self): raise RuntimeError("invalid credentials")
    monkeypatch.setattr(cli, "Collector", BadCollector)
    monkeypatch.setattr(sys, "argv", ["ad-enum", "scan", "--dc-ip", "10.0.0.1",
                                       "--domain", "example.test", "--username", "u",
                                       "--password", "bad", "--output-dir", str(tmp_path)])
    assert cli.main() == 2
    assert "Credentials Invalid" in capsys.readouterr().out
    assert not (tmp_path / "example.test").exists()
