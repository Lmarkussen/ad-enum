from ad_enum import cred1_runtime


def test_cred1_runtime_rejects_tunnel_without_capture(monkeypatch):
    monkeypatch.setattr(cred1_runtime, "_route_interface", lambda target: "tailscale0")
    monkeypatch.setattr(cred1_runtime, "find_library", lambda name: "/lib/libpcap.so")
    monkeypatch.setattr(cred1_runtime, "_effective_capabilities", lambda: 0)
    result = cred1_runtime.check_cred1_runtime("10.1.10.41")
    assert result["status"] == "NOT TESTED"
    assert any("tunnel" in item for item in result["reasons"])
    assert any("CAP_NET_RAW" in item for item in result["reasons"])


def test_cred1_runtime_ready_on_direct_linux_interface(monkeypatch):
    monkeypatch.setattr(cred1_runtime.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cred1_runtime, "_route_interface", lambda target: "eth0")
    monkeypatch.setattr(cred1_runtime, "find_library", lambda name: "/lib/libpcap.so")
    monkeypatch.setattr(cred1_runtime, "_effective_capabilities", lambda: (1 << 12) | (1 << 13))
    result = cred1_runtime.check_cred1_runtime("10.1.10.41")
    assert result["status"] == "READY"
    assert result["interface"] == "eth0"
