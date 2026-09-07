"""Normalize LDAP-shaped AD CS records without depending on ldap3 Entry objects."""
from collections import defaultdict, deque
import struct
from .models import CA, Template
from .security import parse_security_descriptor_safe
from .rights import derive_template_rights, effective_enrollment
from .security import sid_from_bytes
from .core.provenance import Provenance

def values(record, key, default=None):
    value = record.get(key, default)
    if value is None: return default
    return value if isinstance(value, list) else [value]

def sid_value(value):
    if isinstance(value, (bytes, bytearray)):
        try: return sid_from_bytes(value)
        except (IndexError, struct.error, ValueError): return ""
    return str(value)

def normalize_directory(raw):
    cas = [CA(str(values(x, "cn", [""])[0]), str(values(x, "dNSHostName", [""])[0]),
           str(x.get("distinguishedName", "")), [str(v) for v in values(x, "certificateTemplates", [])],
           values(x, "cACertificate", [None])[0], parse_security_descriptor_safe(values(x, "nTSecurityDescriptor", [b""])[0])[0], x,
           [Provenance("ldap-native", "CA collector", str(x.get("distinguishedName", "")))])
           for x in raw.get("cas", [])]
    identities = raw.get("identities", [])
    sid_by_dn = {str(x.get("distinguishedName", "")).lower(): sid_value(values(x, "objectSid", [""])[0]) for x in identities}
    names = {sid: str(values(x, "sAMAccountName", [sid])[0]) for x, sid in [(x, sid_by_dn.get(str(x.get("distinguishedName", "")).lower(), "")) for x in identities] if sid}
    parents = defaultdict(set)
    for group in identities:
        group_sid = sid_by_dn.get(str(group.get("distinguishedName", "")).lower())
        for member_dn in values(group, "member", []):
            member_sid = sid_by_dn.get(str(member_dn).lower())
            if member_sid and group_sid: parents[member_sid].add(group_sid)
    def expand(sid):
        out, q = {sid}, deque([sid])
        while q:
            for parent in parents[q.popleft()]:
                if parent not in out: out.add(parent); q.append(parent)
        return out
    domain_sid = raw.get("domain_sid")
    if not domain_sid:
        domain_sid = next((s.rsplit("-", 1)[0] for s in sid_by_dn.values()
                           if s.rsplit("-", 1)[-1] in {"512", "513", "515", "519"}), None)
    # Primary groups are omitted from AD's member/memberOf links. They still
    # participate in both privilege classification and enrollment access checks.
    for identity in identities:
        sid = sid_by_dn.get(str(identity.get("distinguishedName", "")).lower(), "")
        if not sid:
            continue
        for dn in values(identity, "memberOf", []):
            if str(dn).lower() in sid_by_dn:
                parents[sid].add(sid_by_dn[str(dn).lower()])
        primary = values(identity, "primaryGroupID", [])
        if primary and sid.startswith("S-1-5-21-"):
            parents[sid].add(f"{sid.rsplit('-', 1)[0]}-{primary[0]}")
    universal = {"S-1-1-0", "S-1-5-11"}
    low = set(universal)
    if domain_sid:
        low.update({f"{domain_sid}-513", f"{domain_sid}-515"})
    privileged = {f"S-1-5-32-{rid}" for rid in (544, 548, 549, 550, 551)}
    if domain_sid:
        privileged.update(f"{domain_sid}-{rid}" for rid in (500, 512, 516, 518, 519, 521))
    for identity in identities:
        sid = sid_by_dn.get(str(identity.get("distinguishedName", "")).lower(), "")
        classes = {str(v).lower() for v in values(identity, "objectClass", [])}
        if not sid or "group" in classes:
            continue
        if int((values(identity, "userAccountControl", [0]) or [0])[0]) & 2:
            continue
        admin_count = (values(identity, "adminCount", [0]) or [0])[0]
        admin_count_lower = (values(identity, "admincount", [0]) or [0])[0]
        if str(admin_count).lower() in {"1", "true"} or str(admin_count_lower).lower() in {"1", "true"}:
            continue
        if expand(sid) & privileged:
            continue
        low.add(sid)
    # Never combine unrelated users' groups into one token, or evaluate a group
    # allow independently of a deny that also applies to its members.
    tokens = {sid: expand(sid) | universal for sid in low
              if not (expand(sid) & privileged)}
    subjects = set(tokens)
    templates = []
    for x in raw.get("templates", []):
        sd, sd_warnings = parse_security_descriptor_safe(values(x, "nTSecurityDescriptor", [b""])[0])
        enroll, auto, _ = derive_template_rights(sd); effective = effective_enrollment(sd, subjects, principal_tokens=tokens)
        name = str(values(x, "cn", [""])[0]); flags = int(values(x, "msPKI-Certificate-Name-Flag", [0])[0] or 0)
        enroll_evidence = {sid: effective[sid] for sid in effective}
        templates.append(Template(name=name, display_name=str(values(x, "displayName", [name])[0]),
            dn=str(x.get("distinguishedName", "")), name_flags=flags,
            enrollment_flags=int(values(x, "msPKI-Enrollment-Flag", [0])[0] or 0),
            ekus=[str(v) for v in values(x, "pKIExtendedKeyUsage", [])],
            application_policies=[str(v) for v in values(x, "msPKI-Certificate-Application-Policy", [])],
            enroll_sids=set(effective), enrollment_evidence=enroll_evidence,
            enroll_principals=[names.get(s, s) for s in effective],
            manager_approval=bool(int(values(x, "msPKI-Enrollment-Flag", [0])[0] or 0) & 2),
            authorized_signatures=int(values(x, "msPKI-RA-Signature", [0])[0] or 0), security_descriptor=sd,
            evidence={"raw_attributes": x, "enrollment_ace_evidence": enroll, "autoenrollment_ace_evidence": auto,
                      "low_privileged_sids": low, "low_privileged_subject_sids": subjects,
                      "group_membership": parents, "principal_tokens": tokens, "warnings": sd_warnings},
            provenance=[Provenance("ldap-native", "template collector", str(x.get("distinguishedName", ""))) ]))
    return raw.get("defaultNamingContext", ""), cas, templates
