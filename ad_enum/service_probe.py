"""Bounded network probes for already-known domain hosts.

This module intentionally reports reachability only. It does not authenticate,
execute commands, negotiate coercion, or scan arbitrary address ranges.
"""
import socket
import ssl

from .protocols import parse_http_service, parse_rdp_negotiation, parse_tds_prelogin


DEFAULT_SERVICES = {
    22: "SSH",
    135: "RPC",
    445: "SMB",
    389: "LDAP",
    636: "LDAPS",
    3389: "RDP",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    80: "HTTP",
    443: "HTTPS",
    8530: "WSUS HTTP",
    8531: "WSUS HTTPS",
}


def _recv_bounded(connection, limit=16384):
    chunks, total = [], 0
    while total < limit:
        chunk = connection.recv(min(4096, limit - total))
        if not chunk:
            break
        chunks.append(chunk); total += len(chunk)
        if b"\r\n\r\n" in b"".join(chunks):
            break
    return b"".join(chunks)


def _http_probe(address, port, *, host, timeout, connector, expected=None):
    """Send one bounded HTTP request and return parsed headers/signatures."""
    secure = port in {443, 5986, 8531}
    connection = connector((address, port), timeout=timeout)
    try:
        if secure:
            context = ssl.create_default_context()
            connection = context.wrap_socket(connection, server_hostname=host or address)
        path = "/wsman" if expected == "winrm" else "/"
        method = "OPTIONS" if expected == "webdav" else "GET"
        request = f"{method} {path} HTTP/1.1\r\nHost: {host or address}\r\nConnection: close\r\nUser-Agent: AD-Enum/1\r\n\r\n".encode()
        connection.sendall(request)
        parsed = parse_http_service(_recv_bounded(connection), expected=expected)
        parsed["tls"] = "NEGOTIATED" if secure else "NOT USED"
        parsed["port"] = port
        return parsed
    except ssl.SSLError as exc:
        return {"protocol_state": "TLS ERROR", "error_class": type(exc).__name__, "evidence": []}
    finally:
        try:
            connection.close()
        except OSError:
            pass


def _tds_probe(address, port, *, timeout, connector):
    """Perform a minimal TDS PRELOGIN exchange; no LOGIN7/authentication."""
    # TDS packet type 0x12 is PRELOGIN. This request advertises version and
    # encryption options and contains no account or credential material.
    # The offsets are relative to the PRELOGIN payload.  The option table
    # occupies 11 bytes, followed by the 6-byte version and 1-byte
    # encryption value.
    payload = bytes([0x00, 0x00, 0x0b, 0x00, 0x06,
                     0x01, 0x00, 0x11, 0x00, 0x01, 0xff,
                     0x0f, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])
    packet = bytes([0x12, 0x00]) + (len(payload) + 8).to_bytes(2, "big") + b"\x00\x00\x01\x00" + payload
    connection = connector((address, port), timeout=timeout)
    try:
        connection.sendall(packet)
        # A PRELOGIN response is a single bounded TDS packet. Avoid waiting
        # for a stream delimiter that TDS does not use.
        return parse_tds_prelogin(connection.recv(8192))
    finally:
        try:
            connection.close()
        except OSError:
            pass


def _rdp_probe(address, port, *, timeout, connector):
    """Perform X.224 negotiation only; no CredSSP or interactive login."""
    request = bytes.fromhex("030000130ed000001234000200080003000000")
    connection = connector((address, port), timeout=timeout)
    try:
        connection.sendall(request)
        return parse_rdp_negotiation(_recv_bounded(connection, 4096))
    finally:
        try:
            connection.close()
        except OSError:
            pass


def probe_known_services(targets, *, ports=None, timeout=1.5, max_hosts=64, connector=None):
    """Probe a bounded list of known target IPs/hostnames with TCP connect."""
    connector = connector or socket.create_connection
    ports = ports or DEFAULT_SERVICES
    results, seen = [], set()
    for target in list(targets or [])[:max_hosts]:
        if not isinstance(target, dict):
            continue
        host = target.get("fqdn") or target.get("hostname") or target.get("host")
        ips = target.get("ips") or target.get("ip_addresses") or ([target.get("ip")] if target.get("ip") else [])
        for address in ips or [host]:
            if not address:
                continue
            for port, name in ports.items():
                key = (str(address), int(port))
                if key in seen:
                    continue
                seen.add(key)
                item = {"host": host or str(address), "ip": str(address), "service": name,
                        "port": int(port), "protocol": "tcp", "reachable": False,
                        "state": "CLOSED", "protocol_state": "CLOSED / UNREACHABLE",
                        "source": "bounded-tcp-connect"}
                try:
                    connection = connector((str(address), int(port)), timeout=timeout)
                    try:
                        connection.close()
                    except OSError:
                        pass
                    item.update(reachable=True, state="OPEN", protocol_state="TCP OPEN")
                except (OSError, TimeoutError):
                    pass
                if item["reachable"]:
                    try:
                        if int(port) in {80, 443}:
                            item.update(_http_probe(str(address), int(port), host=host,
                                                     timeout=timeout, connector=connector))
                        elif int(port) in {5985, 5986}:
                            item.update(_http_probe(str(address), int(port), host=host,
                                                     timeout=timeout, connector=connector, expected="winrm"))
                        elif int(port) in {8530, 8531}:
                            item.update(_http_probe(str(address), int(port), host=host,
                                                     timeout=timeout, connector=connector))
                        elif int(port) == 3389:
                            item.update(_rdp_probe(str(address), int(port), timeout=timeout, connector=connector))
                        elif str(name).upper() == "MSSQL" or int(port) in {1433, 1434}:
                            item.update(_tds_probe(str(address), int(port), timeout=timeout, connector=connector))
                    except (OSError, TimeoutError, ssl.SSLError) as exc:
                        item.update(protocol_state="NEGOTIATION ERROR", error_class=type(exc).__name__)
                results.append(item)
    return results
