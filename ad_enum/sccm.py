"""Read-only SCCM/MECM infrastructure inventory and correlation."""
import re


def _values(attrs, key):
    value = attrs.get(key, [])
    return value if isinstance(value, list) else ([value] if value not in (None, "") else [])


def parse_sccm_publication(objects):
    """Normalize only SCCM-specific publication evidence; no hostname guesses."""
    result = {"objects": [], "site_codes": [], "roles": [], "endpoints": []}
    for obj in objects or []:
        if not isinstance(obj, dict):
            continue
        attrs = {str(k).lower(): v for k, v in obj.items()}
        values = []
        for key in ("keywords", "mssms-assignment-site-code", "mssms-site-code"):
            values.extend(str(v) for v in _values(attrs, key))
        site_codes = sorted({m.upper() for value in values for m in re.findall(r"\b[A-Z][A-Z0-9]{2}\b", value)})
        for code in site_codes:
            if code not in result["site_codes"]: result["site_codes"].append(code)
        roles = [str(v) for v in _values(attrs, "mssms-site-system-roles")]
        bindings = [str(v) for v in _values(attrs, "servicebindinginformation")]
        dns = [str(v) for v in (_values(attrs, "servicednsname") + _values(attrs, "dnshostname"))]
        item = {"dn": obj.get("distinguishedName", ""), "object_class": _values(attrs, "objectclass"),
                "site_codes": site_codes, "roles": roles, "service_dns_names": dns,
                "service_bindings": bindings, "raw": obj}
        result["objects"].append(item)
        result["roles"].extend(roles)
        result["endpoints"].extend({"host": host, "source": obj.get("distinguishedName", "")}
                                    for host in dns if host)
    result["roles"] = sorted(set(result["roles"]))
    result["endpoints"] = sorted(result["endpoints"], key=lambda x: (x["host"], x["source"]))
    result["site_codes"] = sorted(set(result["site_codes"]))
    return result

def discover(inventory, raw=None):
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
    publication = parse_sccm_publication((raw or {}).get("sccm", []))
    for endpoint in publication["endpoints"]:
        for host in hosts:
            if endpoint["host"].lower() in {host["name"].lower(), host["fqdn"].lower()}:
                host.setdefault("sccm_evidence", []).append(endpoint)
                host["role"] = "confirmed-sccm-published-host"
                host["confidence"] = "sccm-publication"
    return {"hosts": hosts, "relationships": relationships, "spn_accounts": spn_accounts,
            "publication": publication,
            "site_code": None, "management_points": [], "distribution_points": [],
            "site_servers": [], "sms_providers": [], "sql_servers": [x for x in hosts if x["role"] == "sql-candidate"],
            "pxe": {"status": "UNKNOWN", "evidence": []},
            "sup_wsus": [], "status": "sccm-publication-and-inventory"}


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
