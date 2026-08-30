"""Small normalizers for AD-integrated DNS LDAP-shaped evidence."""
import base64
import ipaddress
import struct

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
        base = {"zone": _one(row.get("zone")), "name": _one(row.get("name") or row.get("dc")),
                "fqdn": _one(row.get("fqdn")), "type": str(_one(row.get("type") or row.get("recordType"), "UNKNOWN")).upper(),
                "value": _one(row.get("value") or row.get("address") or row.get("target")),
                "ttl": _one(row.get("ttl")), "source": row.get("source", "native-ldap")}
        records = row.get("dnsRecord") or row.get("dnsrecord")
        if records and not isinstance(records, list): records = [records]
        for raw in records or []:
            decoded = decode_dns_record(raw, base["name"], base["zone"])
            if decoded:
                result.append({**base, **decoded})
        if not records:
            result.append(base)
    return result

def _dns_name(data, offset=0):
    labels = []
    while offset < len(data):
        length = data[offset]; offset += 1
        if length == 0: break
        if length & 0xC0 or offset + length > len(data): return ""
        labels.append(data[offset:offset + length].decode("ascii", "replace")); offset += length
    return ".".join(labels)

def decode_dns_record(value, name="", zone=""):
    """Decode the AD DNS_RECORD wire value for common record types."""
    if isinstance(value, dict) and "base64" in value:
        try: value = base64.b64decode(value["base64"])
        except Exception: return None
    if isinstance(value, str):
        try: value = base64.b64decode(value)
        except Exception: return None
    if not isinstance(value, (bytes, bytearray)) or len(value) < 24: return None
    try:
        length, record_type = struct.unpack_from("<HH", value, 0)
        ttl = struct.unpack_from("<I", value, 12)[0]
        timestamp = struct.unpack_from("<I", value, 20)[0]
        data = bytes(value[24:24 + length])
        types = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 28: "AAAA", 33: "SRV"}
        kind = types.get(record_type)
        if not kind: return None
        if kind == "A" and len(data) == 4: target = str(ipaddress.ip_address(data))
        elif kind == "AAAA" and len(data) == 16: target = str(ipaddress.ip_address(data))
        elif kind in {"CNAME", "NS", "PTR"}: target = _dns_name(data)
        elif kind == "MX" and len(data) >= 3: target = _dns_name(data, 2); target = f"{struct.unpack_from('<H', data)[0]} {target}"
        elif kind == "SRV" and len(data) >= 7:
            priority, weight, port = struct.unpack_from("<HHH", data)
            target = f"{priority} {weight} {port} {_dns_name(data, 6)}"
        else: return None
        fqdn = str(name or "").rstrip(".")
        if zone and fqdn and "." not in fqdn: fqdn = f"{fqdn}.{str(zone).strip('.')}"
        return {"fqdn": fqdn, "type": kind, "value": target, "ttl": ttl,
                "timestamp": timestamp, "source": "ad-dns"}
    except (IndexError, struct.error, ValueError):
        return None

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
        elif row["type"] == "CNAME":
            item.setdefault("aliases", [])
            if value not in item["aliases"]: item["aliases"].append(str(value).rstrip("."))
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
