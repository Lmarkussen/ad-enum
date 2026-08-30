"""Native security-posture normalizers for LDAP, SMB, trusts, ACLs, and LAPS."""
import re
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
                                 "inherited_object_type": str(a.inherited_object_type) if a.inherited_object_type else None,
                                 "inherited": a.inherited, "applies_to_object": a.applies_to_object} for a in aces],
                       "warnings": warnings})
    return result


def normalize_security_descriptors(rows):
    """Normalize the narrow high-value descriptor collection from LDAP."""
    result = []
    for row in rows or []:
        if not isinstance(row, dict): continue
        sd = _one(row.get("nTSecurityDescriptor"), b"")
        aces, warnings = parse_security_descriptor_safe(sd)
        name = _one(row.get("sAMAccountName") or row.get("cn") or row.get("name"))
        result.append({"target": name or row.get("distinguishedName", ""),
                       "dn": row.get("distinguishedName", ""),
                       "sid": _one(row.get("objectSid")),
                       "object_class": row.get("objectClass", []),
                       "aces": [{"sid": a.sid, "kind": a.kind, "mask": a.mask,
                                 "object_type": str(a.object_type) if a.object_type else None,
                                 "inherited_object_type": str(a.inherited_object_type) if a.inherited_object_type else None,
                                 "inherited": a.inherited, "applies_to_object": a.applies_to_object}
                                for a in aces],
                       "warnings": warnings})
    return result


def normalize_gpo_links(rows):
    """Parse gPLink/gPOptions without attempting full policy processing.

    AD stores links as a bracketed list of LDAP URLs with an option suffix.
    Bit 0 disables a link and bit 1 marks it enforced.  gPOptions bit 0 is
    the block-inheritance flag on the target container.
    """
    result = []
    pattern = re.compile(r"\[LDAP://([^;\]]+);(\d+)\]", re.I)
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        def first(key, default=""):
            value = row.get(key, default)
            return value[0] if isinstance(value, list) and value else (default if value is None else value)
        raw = first("gPLink") or ""
        links = []
        for order, match in enumerate(pattern.finditer(str(raw)), 1):
            dn, option_text = match.groups()
            try: options = int(option_text)
            except ValueError: options = 0
            guid_match = re.search(r"CN=\{([^}]+)\}", dn, re.I)
            links.append({"guid": (guid_match.group(1) if guid_match else "").lower(),
                          "gpo_dn": dn, "link_order": order, "options": options,
                          "enabled": not bool(options & 1), "enforced": bool(options & 2)})
        target_dn = str(row.get("distinguishedName", ""))
        result.append({"target_dn": target_dn, "target_type": first("targetType", "unknown"),
                       "links": links, "block_inheritance": bool(int(first("gPOptions", 0) or 0) & 1),
                       "raw_gPLink": raw, "raw_gPOptions": first("gPOptions", 0)})
    return result


def attach_gpo_links(gpos, link_rows):
    """Attach scope context to normalized GPO records by GUID."""
    by_guid = {str(g.get("guid", "")).strip("{}").lower(): g for g in gpos or []}
    for gpo in gpos or []:
        gpo["links"] = []
    for target in normalize_gpo_links(link_rows):
        for link in target["links"]:
            gpo = by_guid.get(link["guid"])
            if not gpo:
                continue
            gpo["links"].append({**link, "target_dn": target["target_dn"],
                                  "target_type": target["target_type"],
                                  "block_inheritance": target["block_inheritance"]})
    for gpo in gpos or []:
        enabled = [x for x in gpo["links"] if x["enabled"]]
        gpo["scope"] = {"linked": bool(gpo["links"]), "enabled_links": len(enabled),
                         "enforced_links": sum(x["enforced"] for x in enabled),
                         "targets": [x["target_dn"] for x in enabled],
                         "high_impact": any(_high_impact_scope(x["target_dn"]) for x in enabled)}
    return gpos


def _high_impact_scope(dn):
    text = str(dn).upper()
    return ("DC=" in text and text.startswith("DC=") or
            "OU=DOMAIN CONTROLLERS" in text or
            "OU=ADMIN" in text or "OU=PRIVILEG" in text)


_GENERIC_WRITE = 0x40000000
_WRITE_PROPERTY = 0x00000020
_CONTROL_ACCESS = 0x00000100
_RESET_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
_MEMBER_ATTRIBUTE = "bf9679c0-0de6-11d0-a285-00aa003049e2"
_SPN_ATTRIBUTE = "f3a64788-5306-11d1-a9c5-0000f80367c1"
_DANGEROUS = ((0x10000000, "GenericAll"), (_GENERIC_WRITE, "GenericWrite"),
              (0x00040000, "WriteDacl"), (0x00080000, "WriteOwner"),
              (_WRITE_PROPERTY, "WriteProperty"))


def _right_names(mask, ace, row):
    names = [name for bit, name in _DANGEROUS if mask & bit]
    object_type = str(ace.get("object_type") or "").lower()
    target_classes = {str(x).lower() for x in (row.get("object_class") or [])}
    if mask & _CONTROL_ACCESS and object_type == _RESET_PASSWORD:
        names.append("ResetPassword")
    if mask & _WRITE_PROPERTY and object_type == _MEMBER_ATTRIBUTE and "group" in target_classes:
        names.append("ModifyGroupMembership")
    if mask & _WRITE_PROPERTY and object_type == _SPN_ATTRIBUTE:
        names.append("WriteServicePrincipalName")
    return list(dict.fromkeys(names))


def _inventory_maps(inventory):
    records = {}
    for kind_records in inventory.records.values():
        for record in kind_records.values():
            records[str(record.identifier).lower()] = record
            dn = str(record.attributes.get("distinguishedName", "")).lower()
            if dn: records[dn] = record
    return records


def _principal_is_low_priv(sid, inventory, maps, seen=None):
    sid = str(sid)
    seen = set() if seen is None else seen
    if sid.lower() in seen:
        return False, "cyclic-group-membership"
    seen.add(sid.lower())
    if sid in {"S-1-1-0", "S-1-5-11"} or sid.rsplit("-", 1)[-1] in {"513", "515"}:
        return True, "broad-or-domain-users"
    record = maps.get(sid.lower())
    if not record:
        return False, "unknown"
    name = str(record.attributes.get("sAMAccountName") or record.attributes.get("name") or "").lower()
    privileged = {"domain admins", "enterprise admins", "administrators", "schema admins",
                  "account operators", "server operators", "backup operators", "dnsadmins",
                  "group policy creator owners", "domain controllers"}
    if name in privileged or sid.rsplit("-", 1)[-1] in {"512", "519", "544", "548", "549", "550"}:
        return False, "expected-privileged"
    classes = {str(x).lower() for x in (record.attributes.get("objectClass") or [])}
    if "user" in classes or "computer" in classes:
        return True, "ordinary-identity"
    # A custom group is low-privilege only when its known membership reaches
    # an ordinary identity.  Empty/unknown groups remain unresolved.
    members = record.attributes.get("member") or []
    for member_dn in members if isinstance(members, list) else [members]:
        child = maps.get(str(member_dn).lower())
        if child:
            child_low, _ = _principal_is_low_priv(child.identifier, inventory, maps, seen)
            if child_low: return True, "nested-ordinary-membership"
    return False, "unresolved-group"


def analyze_effective_acls(rows, inventory, *, target_filter=None, expected_principal_sids=None):
    """Return narrow, explainable effective dangerous-right observations.

    Denies are applied before allows for the relevant principal.  This is a
    conservative finding-oriented model; raw ACEs remain available for a
    complete Windows security-descriptor audit.
    """
    maps = _inventory_maps(inventory)
    expected_principal_sids = {str(x).lower() for x in (expected_principal_sids or set())}
    observations = []
    for row in rows or []:
        target = str(row.get("gpo") or row.get("target") or row.get("dn") or "")
        if target_filter and not target_filter(row): continue
        aces = row.get("aces", [])
        by_sid = {}
        for ace in aces:
            sid = str(ace.get("sid", ""))
            if not sid or ace.get("kind") not in {"allow", "deny"} or not ace.get("applies_to_object", True): continue
            by_sid.setdefault(sid, []).append(ace)
        for sid, principal_aces in by_sid.items():
            # The authenticated scanner identity is commonly the creator of
            # a test/managed object.  Its creator-owner control is expected
            # administrative context, not a low-privilege delegation finding.
            if sid.lower() in expected_principal_sids:
                continue
            low, context = _principal_is_low_priv(sid, inventory, maps)
            if not low: continue
            denied = 0; allowed = 0; evidence = []
            for ace in principal_aces:
                object_class_guid = row.get("object_class_guid")
                if (ace.get("object_type") and object_class_guid and
                        str(ace["object_type"]).lower() != str(object_class_guid).lower()):
                    continue
                mask = int(ace.get("mask", 0) or 0)
                if ace["kind"] == "deny": denied |= mask
                else: allowed |= mask
                evidence.append(ace)
            effective = allowed & ~denied
            rights = []
            for ace in principal_aces:
                if ace.get("kind") == "allow":
                    rights.extend(_right_names(int(ace.get("mask", 0) or 0) & effective, ace, row))
            rights = list(dict.fromkeys(rights))
            if rights:
                observations.append({"target": target, "principal_sid": sid,
                                      "principal_context": context, "low_privilege": True,
                                      "effective_rights": rights, "effective_mask": effective,
                                      "aces": evidence})
    return observations

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
