"""LAB/OFFLINE ONLY: realistic LDAP-shaped AD CS records for regression tests."""
import struct
from uuid import UUID
from .security import ENROLL_GUID
from .normalize import normalize_directory

DOMAIN = "S-1-5-21-111-222-333"
USER_DN = "CN=Domain Users,DC=example,DC=test"
GROUP_A = "CN=Helpdesk Users,DC=example,DC=test"
GROUP_B = "CN=PKI Enrollment Group,DC=example,DC=test"

def _sid(s):
    p=s.split("-"); return bytes([int(p[1]),len(p)-3])+int(p[2]).to_bytes(6,"big")+b"".join(struct.pack("<I",int(x)) for x in p[3:])
def _ace(s, allow=True, mask=0x100, object_type=None, flags=0, generic=False):
    sb=_sid(s); mask = 0x10000000 if generic else mask; typ=0 if allow else 1
    if object_type: return struct.pack("<BBHII",5 if allow else 6,flags,28+len(sb),mask,1)+UUID(str(object_type)).bytes_le+sb
    return struct.pack("<BBHI",typ,flags,8+len(sb),mask)+sb
def _sd(*aces):
    acl=struct.pack("<BBHHH",2,0,8+sum(map(len,aces)),len(aces),0)+b"".join(aces)
    return struct.pack("<BBHIIII",1,0,0x8004,0,0,0,20)+acl

def ldap_fixture(scenario="A"):
    enroll_sid = "S-1-5-11"
    sd = _sd(_ace(enroll_sid, object_type=ENROLL_GUID))
    if scenario == "D": sd = _sd(_ace(f"{DOMAIN}-512", object_type=ENROLL_GUID))
    if scenario == "H":
        sd = _sd(_ace(f"{DOMAIN}-2002", object_type=ENROLL_GUID))
    if scenario == "I": sd = _sd(_ace("S-1-5-11", object_type=ENROLL_GUID))
    if scenario == "J": sd = _sd(_ace("S-1-5-11", False, object_type=ENROLL_GUID), _ace("S-1-5-11", True, object_type=ENROLL_GUID))
    flags = 1 if scenario != "E" else 0
    ekus = ["1.3.6.1.5.5.7.3.2"] if scenario not in {"F"} else ["1.2.3.4"]
    if scenario == "B": enroll_flags = 2
    else: enroll_flags = 0
    ra = 1 if scenario == "C" else 0
    if scenario == "G": ca_templates = []
    else: ca_templates = ["Lab-ESC1"]
    identities = [
        {"distinguishedName": USER_DN, "objectSid": f"{DOMAIN}-513", "sAMAccountName":"Domain Users", "objectClass":["top", "group"]},
        {"distinguishedName": GROUP_A, "objectSid": f"{DOMAIN}-2001", "sAMAccountName":"Helpdesk Users", "objectClass":["top", "group"], "member":[USER_DN]},
        {"distinguishedName": GROUP_B, "objectSid": f"{DOMAIN}-2002", "sAMAccountName":"PKI Enrollment Group", "objectClass":["top", "group"], "member":[GROUP_A]},
    ]
    return {"defaultNamingContext":"DC=example,DC=test", "domain_sid":DOMAIN, "identities":identities,
      "cas": [{"distinguishedName":"CN=LabCA,CN=Enrollment Services,CN=Public Key Services,DC=example,DC=test",
                "cn":"LabCA", "dNSHostName":"ca.example.test", "certificateTemplates":ca_templates}],
      "templates": [{"distinguishedName":"CN=Lab-ESC1,CN=Certificate Templates,CN=Public Key Services,DC=example,DC=test",
        "cn":"Lab-ESC1", "displayName":"Lab ESC1", "objectGUID":b"0123456789abcdef",
        "msPKI-Certificate-Name-Flag":flags, "msPKI-Enrollment-Flag":enroll_flags,
        "msPKI-RA-Signature":ra, "pKIExtendedKeyUsage":ekus,
        "msPKI-Certificate-Application-Policy":[], "nTSecurityDescriptor":sd}]}

def collect_fixture(scenario="A"):
    return normalize_directory(ldap_fixture(scenario))
