"""Bounded network probes for already-known domain hosts.

This module intentionally reports reachability only. It does not authenticate,
execute commands, negotiate coercion, or scan arbitrary address ranges.
"""
import socket


DEFAULT_SERVICES = {
    135: "RPC",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    80: "HTTP",
    443: "HTTPS",
    8530: "WSUS HTTP",
    8531: "WSUS HTTPS",
}


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
                        "state": "CLOSED", "source": "bounded-tcp-connect"}
                try:
                    connection = connector((str(address), int(port)), timeout=timeout)
                    try:
                        connection.close()
                    except OSError:
                        pass
                    item.update(reachable=True, state="OPEN")
                except (OSError, TimeoutError):
                    pass
                results.append(item)
    return results
