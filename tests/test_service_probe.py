from ad_enum.service_probe import probe_known_services
from ad_enum.protocols import parse_tds_prelogin, parse_http_service, parse_rdp_negotiation


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
    assert result[0]["protocol_state"] == "TCP OPEN"
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


def test_tds_prelogin_parser_confirms_protocol_and_encryption():
    # TDS header + VERSION and ENCRYPTION option table, followed by payloads.
    packet = bytearray(b"\x04\x01\x00\x1a\x00\x00\x01\x00")
    packet.extend(bytes([0x00, 0x00, 0x13, 0x00, 0x06, 0x01, 0x00, 0x19, 0x00, 0x01, 0xff]))
    packet.extend(b"\x0f\x00\x00\x00\x01\x00\x03")
    result = parse_tds_prelogin(packet)
    assert result["tds"] == "CONFIRMED"
    assert result["encryption"] == "REQUIRED"


def test_protocol_parsers_reject_false_positive_tcp_data():
    assert parse_tds_prelogin(b"HTTP/1.1 200 OK")["tds"] == "UNKNOWN"
    assert parse_rdp_negotiation(b"\x03\x00garbage")["rdp"] == "UNKNOWN"


def test_http_winrm_and_webdav_signatures_are_bounded():
    raw = (b"HTTP/1.1 401 Unauthorized\r\nServer: Microsoft-HTTPAPI/2.0\r\n"
           b"WWW-Authenticate: Negotiate\r\nDAV: 1,2\r\nContent-Length: 0\r\n\r\n")
    result = parse_http_service(raw, expected="winrm")
    assert result["wsman"] is True
    assert result["www_authenticate"] == ["Negotiate"]
    assert result["webdav"] is True
