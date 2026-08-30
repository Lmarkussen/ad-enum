"""Current-scan-identity access observations.

This module accepts only observations produced for the active scan identity.
It never reads credentials artifacts and never creates command/shell actions.
"""


AUTH_STATES = {"AUTHENTICATED", "DENIED", "AUTH ERROR", "TIMEOUT", "TOOL FAILURE",
               "NOT TESTED", "NOT APPLICABLE", "PROTOCOL UNAVAILABLE", "UNKNOWN"}


def normalize_access(record):
    record = record if isinstance(record, dict) else {}
    auth = str(record.get("authentication", record.get("auth", "UNKNOWN"))).upper()
    if auth in {"SUCCESS", "AUTHENTICATED", "YES"}:
        auth = "AUTHENTICATED"
    elif auth in {"FAIL", "FAILED", "DENIED", "NO"}:
        auth = "DENIED"
    elif auth not in AUTH_STATES:
        auth = "UNKNOWN"
    privilege = str(record.get("privilege", "UNKNOWN")).upper()
    if privilege not in {"ADMIN", "ELEVATED", "STANDARD", "UNKNOWN"}:
        privilege = "UNKNOWN"
    return {"host": record.get("host", ""), "ip": record.get("ip", ""),
            "roles": sorted({str(x) for x in (record.get("roles", []) or [])}),
            "protocol": str(record.get("protocol", "")).upper(), "port": record.get("port"),
            "principal": record.get("principal", ""), "authentication": auth,
            "privilege": privilege, "source": record.get("source", ""),
            "evidence": record.get("evidence", {}), "error_class": record.get("error_class", "")}


def from_netexec_hosts(hosts, principal):
    """Convert existing NetExec SMB host observations into access records."""
    result = []
    for host in hosts or []:
        if not isinstance(host, dict):
            continue
        authenticated = host.get("smb_authenticated")
        result.append(normalize_access({
            "host": host.get("host") or host.get("name") or host.get("ip"),
            "ip": host.get("ip", ""), "protocol": "SMB", "port": 445,
            "principal": principal, "authentication": "AUTHENTICATED" if authenticated else "DENIED",
            "privilege": "ADMIN" if host.get("admin") is True or host.get("is_admin") is True else "UNKNOWN",
            "source": "NetExec", "evidence": {"smb_authenticated": authenticated,
                                                   "raw": host.get("raw", "")}}))
    return result


def merge_access(records):
    """Deduplicate by host/protocol/port while retaining source evidence."""
    merged = {}
    for record in records or []:
        item = normalize_access(record)
        key = (str(item["host"]).lower(), item["protocol"], item["port"])
        old = merged.get(key)
        if old is None or (old["authentication"] != "AUTHENTICATED" and item["authentication"] == "AUTHENTICATED"):
            merged[key] = item
        elif old is not None and item.get("evidence"):
            old.setdefault("evidence", {}).update(item["evidence"] if isinstance(item["evidence"], dict) else {})
    return sorted(merged.values(), key=lambda x: (str(x["host"]).lower(), x["protocol"], x["port"] or 0))


def parse_netexec_auth(text, *, protocol, host, ip="", principal="", source="NetExec"):
    """Normalize one bounded NetExec authentication result.

    This intentionally recognizes only explicit success/failure markers and
    never treats a TCP/banner line as authentication success.
    """
    text = text or ""
    lowered = text.lower()
    success = any(marker in lowered for marker in ("[+]", "pwn3d!"))
    failure = any(marker in lowered for marker in ("status_logon_failure", "access_denied", "authentication failed", "[-]"))
    authentication = "AUTHENTICATED" if success and not failure else ("DENIED" if failure else "UNKNOWN")
    privilege = "ADMIN" if "pwn3d!" in lowered else "UNKNOWN"
    return normalize_access({"host": host, "ip": ip, "protocol": protocol, "principal": principal,
                             "authentication": authentication, "privilege": privilege,
                             "source": source, "evidence": {"raw_marker": "explicit NetExec result"}})
