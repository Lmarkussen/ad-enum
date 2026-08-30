"""Small normalizers for AD-integrated DNS LDAP-shaped evidence."""

def _one(value, default=""):
    return value[0] if isinstance(value, list) and value else (default if value is None else value)

def normalize_zones(rows):
    return [{"name": _one(x.get("name") or x.get("dc") or x.get("distinguishedName")),
             "dn": x.get("distinguishedName", ""), "source": x.get("source", "native-ldap")}
            for x in rows or [] if isinstance(x, dict)]

def normalize_records(rows):
    result = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        result.append({"zone": _one(row.get("zone")), "name": _one(row.get("name") or row.get("dc")),
                       "fqdn": _one(row.get("fqdn")), "type": str(_one(row.get("type") or row.get("recordType"), "UNKNOWN")).upper(),
                       "value": _one(row.get("value") or row.get("address") or row.get("target")),
                       "ttl": _one(row.get("ttl")), "source": row.get("source", "native-ldap")})
    return result

def merge_into_dns_map(dns_map, records):
    """Merge only address-like records into the existing authoritative map."""
    by_name = {x["fqdn"]: x for x in dns_map.get("records", []) if x.get("fqdn")}
    for row in records or []:
        fqdn, value = str(row.get("fqdn") or "").lower().rstrip("."), row.get("value")
        if not fqdn or row.get("type") not in {"A", "AAAA", "CNAME"} or not value:
            continue
        item = by_name.get(fqdn)
        if not item:
            item = {"fqdn": fqdn, "short_name": fqdn.split(".", 1)[0], "ip_addresses": [],
                    "ipv4_addresses": [], "ipv6_addresses": [], "sources": [],
                    "resolution_methods": [], "conflicts": []}
            dns_map.setdefault("records", []).append(item); by_name[fqdn] = item
        if row["type"] in {"A", "AAAA"}:
            bucket = "ipv6_addresses" if ":" in str(value) else "ipv4_addresses"
            if value not in item[bucket]: item[bucket].append(value)
            if value not in item["ip_addresses"]: item["ip_addresses"].append(value)
        if "ad-dns" not in item["sources"]: item["sources"].append("ad-dns")
        if "native-ad-dns" not in item["resolution_methods"]: item["resolution_methods"].append("native-ad-dns")
    return dns_map

def normalize_password_settings(rows):
    fields = ("msDS-PasswordSettingsPrecedence", "msDS-PasswordReversibleEncryptionEnabled",
              "msDS-PasswordComplexityEnabled", "msDS-MinimumPasswordLength",
              "msDS-PasswordHistoryLength", "msDS-MinimumPasswordAge",
              "msDS-MaximumPasswordAge", "msDS-LockoutThreshold",
              "msDS-LockoutObservationWindow", "msDS-LockoutDuration")
    return [{"name": _one(x.get("name")), "dn": x.get("distinguishedName", ""),
             "applies_to": [_one(v) for v in (x.get("msDS-PSOAppliesTo") or [])],
             "settings": {field: _one(x.get(field)) for field in fields if x.get(field) is not None},
             "source": "native-ldap"} for x in rows or []]
