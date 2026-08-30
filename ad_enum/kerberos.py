"""Read-only account exposure analysis.

This module deliberately identifies exposure conditions only.  It never asks
for AS-REP material, TGS tickets, or attempts authentication with findings.
"""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

UAC = {
    "DONT_REQ_PREAUTH": 0x400000,
    "PASSWD_NOTREQD": 0x20,
    "NORMAL_ACCOUNT": 0x200,
    "DONT_EXPIRE_PASSWORD": 0x10000,
    "ENCRYPTED_TEXT_PWD_ALLOWED": 0x80,
    "USE_DES_KEY_ONLY": 0x200000,
    "SMARTCARD_REQUIRED": 0x40000,
    "TRUSTED_FOR_DELEGATION": 0x80000,
    "NOT_DELEGATED": 0x100000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
    "ACCOUNTDISABLE": 0x2,
}

@dataclass
class AccountExposure:
    username: str
    identifier: str
    enabled: bool
    spns: list[str]
    flags: dict[str, bool]
    attributes: dict
    sources: list[str]

    def as_dict(self): return asdict(self)

def _one(value, default=""):
    return value[0] if isinstance(value, list) and value else (default if value is None else value)

def _uac(record):
    try: return int(_one(record.attributes.get("userAccountControl"), 0) or 0)
    except (TypeError, ValueError): return 0

def account_exposure(record):
    attrs = record.attributes
    value = _uac(record)
    spns = attrs.get("servicePrincipalName", [])
    if isinstance(spns, list) and len(spns) == 1 and isinstance(spns[0], (list, tuple)):
        spns = spns[0]
    if isinstance(spns, str): spns = [spns] if spns else []
    flags = {name: bool(value & bit) for name, bit in UAC.items()}
    return AccountExposure(str(_one(attrs.get("sAMAccountName"), record.identifier)),
                          record.identifier, not flags["ACCOUNTDISABLE"], list(spns), flags,
                          attrs, list(record.sources))

def ad_filetime(value):
    """Convert an AD FILETIME value to UTC, or return None for missing data."""
    try:
        raw = int(_one(value, 0) or 0)
        if raw <= 0:
            return None
        return datetime.fromtimestamp(raw / 10_000_000 - 11644473600, tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None

def account_security_context(item, now=None, *, privileged=False):
    """Return safe, approximate account-age context for reporting."""
    now = now or datetime.now(timezone.utc)
    password_set = ad_filetime(item.attributes.get("pwdLastSet"))
    last_logon = ad_filetime(item.attributes.get("lastLogonTimestamp"))
    return {
        "privileged": bool(privileged),
        "service_account": bool(item.spns),
        "pwdLastSet": password_set.isoformat() if password_set else None,
        "password_age_days": max(0, (now - password_set).days) if password_set else None,
        "lastLogonTimestamp": last_logon.isoformat() if last_logon else None,
        "last_logon_approximate": bool(last_logon),
        "last_logon_age_days": max(0, (now - last_logon).days) if last_logon else None,
    }

PRIVILEGED_RIDS = {"512", "519", "544", "548", "549", "550", "551", "552"}
PRIVILEGED_NAMES = {"domain admins", "enterprise admins", "administrators",
                    "account operators", "server operators", "backup operators", "dnsadmins"}

def privileged_account_sids(inventory):
    """Conservative privilege context; adminCount is retained separately.

    Group membership is expanded from member DNs when both sides are present.
    This is context for prioritization, not proof of an attack path.
    """
    by_dn = {str(r.attributes.get("distinguishedName", "")).lower(): r
             for r in inventory.records.get("users", {}).values()}
    by_dn.update({str(r.attributes.get("distinguishedName", "")).lower(): r
                  for r in inventory.records.get("groups", {}).values()})
    parents = {}
    for group in inventory.records.get("groups", {}).values():
        gs = group.identifier
        attrs = group.attributes
        name = str(_one(attrs.get("sAMAccountName"), "")).lower()
        if gs.upper().startswith("S-") and gs.rsplit("-", 1)[-1] in PRIVILEGED_RIDS or name in PRIVILEGED_NAMES:
            for member in attrs.get("member", []) if isinstance(attrs.get("member", []), list) else [attrs.get("member")]:
                child = by_dn.get(str(member).lower())
                if child: parents.setdefault(child.identifier, set()).add(gs)
    result = set()
    for record in inventory.records.get("users", {}).values():
        if str(record.attributes.get("adminCount", "0")) in {"1", "[1]"}:
            result.add(record.identifier)
        pending = [record.identifier]; seen = set()
        while pending:
            current = pending.pop()
            if current in seen: continue
            seen.add(current)
            groups = parents.get(current, set())
            if groups:
                result.add(record.identifier)
                pending.extend(groups)
    return result

def account_exposures(inventory):
    return [account_exposure(r) for r in inventory.records.get("users", {}).values()]

def roastable(inventory):
    """Return grouped, enabled/disabled AS-REP and SPN exposures."""
    asrep, kerberoast, passwd_not_required = [], [], []
    for record in inventory.records.get("users", {}).values():
        item = account_exposure(record)
        if item.flags["DONT_REQ_PREAUTH"]:
            asrep.append(item)
        if item.spns:
            kerberoast.append(item)
        if item.enabled and item.flags["PASSWD_NOTREQD"]:
            passwd_not_required.append(item)
    return {"asrep": asrep, "kerberoast": kerberoast,
            "password_not_required": passwd_not_required}
