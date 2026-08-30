"""Native security-posture normalizers for LDAP, SMB, trusts, ACLs, and LAPS."""
from .security import parse_security_descriptor_safe

def _one(value, default=""):
    return value[0] if isinstance(value, list) and value else (default if value is None else value)

def normalize_smb(inventory):
    result = []
    for record in inventory.records.get("observed_hosts", {}).values():
        a = record.attributes
        result.append({"host": a.get("host") or a.get("name") or record.identifier, "ip": a.get("ip"),
                       "domain": a.get("domain"), "os": a.get("os"), "smb_signing": a.get("smb_signing"),
                       "smbv1": a.get("smbv1", "unknown"), "sources": list(record.sources), "raw": a})
    return result

def normalize_trusts(rows):
    return [{"dn": row.get("distinguishedName", ""), "partner": _one(row.get("trustPartner")),
             "direction": _one(row.get("trustDirection")), "type": _one(row.get("trustType")),
             "attributes": _one(row.get("trustAttributes")), "sid": _one(row.get("securityIdentifier")),
             "source": "native-ldap"} for row in rows or [] if isinstance(row, dict)]

def normalize_gpo_acls(rows):
    result = []
    for row in rows or []:
        sd = _one(row.get("nTSecurityDescriptor"), b"")
        aces, warnings = parse_security_descriptor_safe(sd)
        name = _one(row.get("displayName"))
        result.append({"gpo": name, "dn": row.get("distinguishedName", ""),
                       "aces": [{"sid": a.sid, "kind": a.kind, "mask": a.mask,
                                 "object_type": str(a.object_type) if a.object_type else None,
                                 "inherited": a.inherited, "applies_to_object": a.applies_to_object} for a in aces],
                       "warnings": warnings})
    return result

def normalize_laps(schema_rows, inventory):
    schema = sorted({_one(row.get("lDAPDisplayName")) for row in schema_rows or [] if _one(row.get("lDAPDisplayName"))})
    families = {"classic": any(x.lower().startswith("ms-mcs-admpwd") for x in schema),
                "windows": any(x.lower().startswith("mslaps-") for x in schema)}
    computers = []
    for record in inventory.records.get("computers", {}).values():
        a = record.attributes
        expiration = {key: _one(a.get(key)) for key in ("ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime", "msLAPS-EncryptedPasswordExpirationTime") if a.get(key)}
        if expiration or families["classic"] or families["windows"]:
            computers.append({"name": _one(a.get("sAMAccountName"), record.identifier), "sid": record.identifier,
                              "managed": bool(expiration), "expiration": expiration, "sources": list(record.sources)})
    return {"schema_attributes": schema, "families": families, "computers": computers, "passwords_retrieved": False}
