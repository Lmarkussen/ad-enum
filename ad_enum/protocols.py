"""Bounded parsers for unauthenticated service-protocol observations."""
import re


def parse_tds_prelogin(data):
    """Parse a SQL Server PRELOGIN response without authenticating."""
    result = {"protocol_state": "UNKNOWN", "tds": "UNKNOWN", "encryption": "UNKNOWN",
              "version": None, "evidence": []}
    if not isinstance(data, (bytes, bytearray)) or len(data) < 8 or data[0] != 0x04:
        result["protocol_state"] = "TCP OPEN"
        result["evidence"].append("not a TDS PRELOGIN packet")
        return result
    declared = int.from_bytes(data[2:4], "big")
    if declared < 8 or declared > len(data):
        result["protocol_state"] = "PROTOCOL PARTIAL"
        result["evidence"].append("invalid TDS packet length")
        return result
    options, cursor = {}, 8
    while cursor < declared:
        if data[cursor] == 0xFF:
            break
        if cursor + 5 > declared:
            result["protocol_state"] = "PROTOCOL PARTIAL"
            return result
        kind = data[cursor]
        offset = int.from_bytes(data[cursor + 1:cursor + 3], "big")
        length = int.from_bytes(data[cursor + 3:cursor + 5], "big")
        cursor += 5
        if offset + length > len(data):
            result["protocol_state"] = "PROTOCOL PARTIAL"
            return result
        options[kind] = data[offset:offset + length]
    result["tds"] = "CONFIRMED"
    result["protocol_state"] = "PROTOCOL CONFIRMED"
    result["evidence"].append("TDS PRELOGIN response")
    encryption = options.get(0x01, b"")
    if encryption:
        result["encryption"] = {0: "OPTIONAL", 1: "REQUIRED", 2: "NOT SUPPORTED", 3: "REQUIRED"}.get(encryption[0], "UNKNOWN")
    version = options.get(0x00, b"")
    if len(version) >= 4:
        result["version"] = ".".join(str(x) for x in version[:4])
    return result


def _headers(raw):
    head = (raw or b"").split(b"\r\n\r\n", 1)[0]
    lines = head.decode("iso-8859-1", "replace").splitlines()
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers.setdefault(key.lower(), []).append(value.strip())
    return lines[0] if lines else "", headers


def parse_http_service(raw, *, expected=None):
    """Fingerprint bounded HTTP response headers and a small body."""
    status_line, headers = _headers(raw)
    result = {"protocol_state": "UNKNOWN", "status_code": None, "server": "",
              "www_authenticate": [], "content_type": "", "location": "", "evidence": []}
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", status_line)
    if match:
        result["status_code"] = int(match.group(1))
        result["protocol_state"] = "PROTOCOL CONFIRMED"
    result["server"] = (headers.get("server") or [""])[0]
    result["www_authenticate"] = headers.get("www-authenticate", [])
    result["content_type"] = (headers.get("content-type") or [""])[0]
    result["location"] = (headers.get("location") or [""])[0]
    body = (raw or b"").split(b"\r\n\r\n", 1)[-1][:16384].decode("utf-8", "replace")
    result["sccm_marker"] = expected == "sccm-mp" and ("SMS_MP" in body or "MPLIST" in body)
    if expected == "winrm":
        result["wsman"] = ("wsman" in body.lower() or "microsoft-httpapi" in result["server"].lower()
                            or result["status_code"] in {401, 405})
        if result["wsman"]:
            result["evidence"].append("WSMan endpoint response")
    else:
        result["wsman"] = False
    result["webdav"] = bool(headers.get("dav") or headers.get("ms-author-via"))
    if result["webdav"]:
        result["evidence"].append("DAV response header")
    return result


def parse_rdp_negotiation(data):
    """Parse bounded X.224/RDP negotiation response, without login."""
    result = {"protocol_state": "UNKNOWN", "rdp": "UNKNOWN", "nla": "UNKNOWN",
              "tls": "UNKNOWN", "selected_protocol": None, "evidence": []}
    if not isinstance(data, (bytes, bytearray)) or len(data) < 12 or data[:2] != b"\x03\x00":
        result["protocol_state"] = "TCP OPEN"
        return result
    if data[5] != 0xD0:
        result["protocol_state"] = "PROTOCOL PARTIAL"
        return result
    result["protocol_state"] = result["rdp"] = "PROTOCOL CONFIRMED"
    result["evidence"].append("X.224 Connection Confirm")
    if len(data) >= 16 and data[11] == 0x02:
        selected = int.from_bytes(data[12:16], "little")
        result["selected_protocol"] = selected
        result["tls"] = "SUPPORTED" if selected & 1 else "NOT OBSERVED"
        result["nla"] = "REQUIRED" if selected & 2 else "NOT OBSERVED"
    return result


def merge_protocol_observation(tcp_observation, protocol):
    """Merge protocol results without losing the original TCP evidence."""
    result = dict(tcp_observation or {})
    result.update(protocol or {})
    if result.get("reachable") and result.get("protocol_state") in (None, "UNKNOWN"):
        result["protocol_state"] = "TCP OPEN"
    return result
