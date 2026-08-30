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
    low = {"S-1-1-0", "S-1-5-11"}
    if domain_sid: low.update({f"{domain_sid}-513", f"{domain_sid}-515"})
    # Domain Users is normally a primary group and therefore is not present in
    # every user's member attribute. Include ordinary user/computer SIDs as
    # candidate low-privilege subjects, while excluding identities whose
    # transitive group membership identifies them as privileged.
    privileged_group_rids = {"512", "519", "544", "548", "549", "550"}
    for identity in identities:
        sid = sid_by_dn.get(str(identity.get("distinguishedName", "")).lower(), "")
        classes = {str(v).lower() for v in values(identity, "objectClass", [])}
        if not sid or (classes and "group" in classes):
            continue
        if any(parent.rsplit("-", 1)[-1] in privileged_group_rids for parent in expand(sid)):
            continue
        low.add(sid)
    subjects = set().union(*(expand(s) for s in low))
    templates = []
    for x in raw.get("templates", []):
        sd, sd_warnings = parse_security_descriptor_safe(values(x, "nTSecurityDescriptor", [b""])[0])
        enroll, auto, _ = derive_template_rights(sd); effective = effective_enrollment(sd, subjects)
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
                      "group_membership": parents, "warnings": sd_warnings},
            provenance=[Provenance("ldap-native", "template collector", str(x.get("distinguishedName", ""))) ]))
    return raw.get("defaultNamingContext", ""), cas, templates
