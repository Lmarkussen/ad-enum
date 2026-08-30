"""Read-only AD delegation normalization."""
from dataclasses import asdict, dataclass, field
import base64
from .kerberos import UAC, account_exposure
from .security import parse_security_descriptor_safe

@dataclass
class DelegationRecord:
    target: str
    target_type: str
    sid: str
    enabled: bool
    kind: str
    targets: list[str] = field(default_factory=list)
    protocol_transition: bool = False
    principals: list[dict] = field(default_factory=list)
    expected_dc: bool = False
    sources: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    def as_dict(self): return asdict(self)

def _one(value, default=""):
    return value[0] if isinstance(value, list) and value else (default if value is None else value)

def _binary(value):
    value = _one(value, b"")
    if isinstance(value, dict) and "base64" in value:
        try: return base64.b64decode(value["base64"])
        except Exception: return b""
    return value

def enumerate_delegation(inventory):
    records = []
    dc_ids = set(inventory.records.get("domain_controllers", {}))
    names = {}
    for kind_records in inventory.records.values():
        for record in kind_records.values():
            names[str(record.identifier).lower()] = str(_one(
                record.attributes.get("sAMAccountName") or record.attributes.get("name"),
                record.identifier))
    for kind in ("users", "computers"):
        for record in inventory.records.get(kind, {}).values():
            exposure = account_exposure(record) if kind == "users" else None
            attrs = record.attributes
            try: flags = int(_one(attrs.get("userAccountControl"), 0) or 0)
            except (TypeError, ValueError): flags = 0
            sid = record.identifier if str(record.identifier).upper().startswith("S-") else str(_one(attrs.get("objectSid"), ""))
            name = str(_one(attrs.get("sAMAccountName"), record.identifier))
            enabled = not bool(flags & UAC["ACCOUNTDISABLE"])
            is_dc = record.identifier.lower() in dc_ids or bool(attrs.get("is_domain_controller"))
            unconstrained = bool(flags & UAC["TRUSTED_FOR_DELEGATION"])
            allowed = _one(attrs.get("msDS-AllowedToDelegateTo"), [])
            if isinstance(allowed, str): allowed = [allowed] if allowed else []
            transition = bool(flags & UAC["TRUSTED_TO_AUTH_FOR_DELEGATION"])
            if unconstrained:
                records.append(DelegationRecord(name, kind[:-1], sid, enabled, "unconstrained",
                    expected_dc=is_dc, sources=list(record.sources),
                    evidence={"userAccountControl": flags, "expected_dc": is_dc}))
            if allowed:
                records.append(DelegationRecord(name, kind[:-1], sid, enabled, "constrained",
                    targets=list(allowed), protocol_transition=transition,
                    sources=list(record.sources), evidence={"msDS-AllowedToDelegateTo": allowed,
                    "userAccountControl": flags}))
            rbcd = _binary(attrs.get("msDS-AllowedToActOnBehalfOfOtherIdentity"))
            if rbcd:
                aces, warnings = parse_security_descriptor_safe(rbcd)
                principals = [{"sid": ace.sid, "name": names.get(ace.sid.lower(), ace.sid),
                               "mask": ace.mask, "ace_type": ace.ace_type,
                               "kind": ace.kind, "raw": ace.raw.hex()} for ace in aces if ace.kind == "allow"]
                records.append(DelegationRecord(name, kind[:-1], sid, enabled, "rbcd",
                    principals=principals, sources=list(record.sources),
                    evidence={"warnings": warnings, "ace_count": len(aces),
                              "impact": "allowed principal may impersonate users to Kerberos services on the target",
                              "principal_context": [{"sid": p["sid"], "name": p["name"],
                                                     "known": p["sid"].lower() in names} for p in principals]}))
    return records

def enumerate_gmsa(inventory):
    """Inventory gMSAs and decode only the ACL, never managed passwords."""
    result = []
    for record in inventory.records.get("gmsa", {}).values():
        attrs = record.attributes
        principals, warnings = [], []
        sd = _binary(attrs.get("msDS-GroupMSAMembership"))
        if sd:
            aces, warnings = parse_security_descriptor_safe(sd)
            principals = [{"sid": ace.sid, "kind": ace.kind, "mask": ace.mask,
                           "raw": ace.raw.hex()} for ace in aces if ace.kind == "allow"]
        spns = attrs.get("servicePrincipalName", [])
        if isinstance(spns, str): spns = [spns]
        try: uac = int(_one(attrs.get("userAccountControl"), 0) or 0)
        except (TypeError, ValueError): uac = 0
        result.append({"identifier": record.identifier,
                       "name": str(_one(attrs.get("sAMAccountName"), record.identifier)),
                       "enabled": not bool(uac & UAC["ACCOUNTDISABLE"]),
                       "spns": list(spns), "principals_allowed_password_retrieval": principals,
                       "warnings": warnings, "sources": list(record.sources)})
    return result
