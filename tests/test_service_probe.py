from ad_enum.service_probe import probe_known_services


def test_known_service_probe_is_bounded_and_normalized():
    calls = []

    class Socket:
        def close(self):
            pass

    def connector(address, timeout):
        calls.append((address, timeout))
        if address[1] == 445:
            return Socket()
        raise OSError("closed")

    result = probe_known_services([{"fqdn": "FILE01.sccm.lab", "ips": ["10.0.0.5"]}],
                                  ports={445: "SMB", 3389: "RDP"}, connector=connector)
    assert len(result) == 2
    assert result[0]["reachable"] is True
    assert result[0]["state"] == "OPEN"
    assert result[1]["state"] == "CLOSED"
    assert all(call[0][0] == "10.0.0.5" for call in calls)


def test_known_service_probe_deduplicates_ip_port():
    calls = []

    def connector(address, timeout):
        calls.append(address)
        raise TimeoutError()

    result = probe_known_services([
        {"fqdn": "a.example", "ips": ["10.0.0.5"]},
        {"fqdn": "b.example", "ips": ["10.0.0.5"]},
    ], ports={445: "SMB"}, connector=connector)
    assert len(result) == 1
    assert len(calls) == 1
