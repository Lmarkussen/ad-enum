"""Read-only SCCM/MECM infrastructure inventory and correlation."""

def discover(inventory):
    hosts = []
    relationships = []
    spn_accounts = []
    for record in inventory.records.get("computers", {}).values():
        attrs = record.attributes
        name = str(attrs.get("name") or attrs.get("cn") or "").rstrip("$")
        spns = attrs.get("servicePrincipalName") or attrs.get("serviceprincipalnames") or []
        if isinstance(spns, str): spns = [spns]
        if spns:
            spn_accounts.append({"account": attrs.get("sAMAccountName", name),
                                 "spns": list(spns), "sources": record.sources})
        hints = []
        if any("MSSQLSvc/" in str(x) for x in spns): hints.append("SQL")
        if any(str(x).upper().startswith(("HTTP/", "WSUS/")) for x in spns): hints.append("management-point-candidate")
        if "MECM" in name.upper() or "SCCM" in name.upper(): hints.append("SCCM-host-candidate")
        if "SQL" in name.upper() or any("MSSQLSvc/" in str(x) for x in spns): hints.append("SQL")
        if hints:
            role = "candidate"
            upper = {x.upper() for x in hints}
            if "SQL" in upper and "SCCM-HOST-CANDIDATE" not in upper: role = "sql-candidate"
            elif "MANAGEMENT-POINT-CANDIDATE" in upper: role = "management-point-candidate"
            elif "SCCM-HOST-CANDIDATE" in upper: role = "site-server-candidate"
            hosts.append({"name": name, "fqdn": attrs.get("dNSHostName", ""),
                          "sid": record.identifier, "role": role,
                          "hints": sorted(set(hints)), "sources": record.sources})
            for hint in sorted(set(hints)):
                relationships.append({"host": name, "role": hint, "confidence": "candidate",
                                      "evidence": {"hints": sorted(set(hints)), "spns": list(spns)}})
    return {"hosts": hosts, "relationships": relationships, "spn_accounts": spn_accounts,
            "site_code": None, "management_points": [], "distribution_points": [],
            "site_servers": [], "sms_providers": [], "sql_servers": [x for x in hosts if x["role"] == "sql-candidate"],
            "pxe": {"status": "UNKNOWN", "evidence": []},
            "sup_wsus": [], "status": "candidate-discovery-only"}


def normalize_relayking(data):
    """Keep RelayKing's structured exposure/path results without executing them."""
    if not isinstance(data, dict):
        return {"status": "UNAVAILABLE", "targets": [], "paths": [], "statistics": {}}
    paths = data.get("relay_paths", [])
    normalized = []
    for path in paths if isinstance(paths, list) else []:
        if not isinstance(path, dict):
            continue
        normalized.append({key: path.get(key) for key in
                           ("source_host", "source_ip", "source_protocol", "dest_host",
                            "dest_ip", "dest_protocol", "impact", "description",
                            "ntlmv1_required")})
    return {"status": "PASS", "targets": data.get("targets", []),
            "paths": normalized, "statistics": data.get("statistics", {}),
            "high_value_targets": data.get("high_value_targets", [])}
