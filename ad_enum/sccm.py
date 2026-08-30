"""Read-only SCCM/MECM infrastructure inventory heuristics."""

def discover(inventory):
    hosts = []
    for record in inventory.records.get("computers", {}).values():
        attrs = record.attributes
        name = str(attrs.get("name") or attrs.get("cn") or "").rstrip("$")
        spns = attrs.get("servicePrincipalName") or attrs.get("serviceprincipalnames") or []
        if isinstance(spns, str): spns = [spns]
        hints = []
        if any("MSSQLSvc/" in str(x) for x in spns): hints.append("SQL")
        if any(str(x).upper().startswith(("HTTP/", "WSUS/")) for x in spns): hints.append("management-point-candidate")
        if "MECM" in name.upper() or "SCCM" in name.upper(): hints.append("SCCM-host-candidate")
        if "SQL" in name.upper() or any("MSSQLSvc/" in str(x) for x in spns): hints.append("SQL")
        if hints:
            hosts.append({"name": name, "sid": record.identifier, "hints": sorted(set(hints)), "sources": record.sources})
    return {"hosts": hosts, "site_code": None, "status": "inventory-candidates-only"}
