from ldap3 import NTLM, Connection, Server
from ldap3.protocol.microsoft import security_descriptor_control
from .models import CA, Template
from .security import parse_security_descriptor_safe
from .rights import effective_enrollment, derive_template_rights
from .identity import Resolver
from .normalize import normalize_directory


def _value(entry, key, default=None):
    value = entry.entry_attributes_as_dict.get(key, default)
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


class Collector:
    def __init__(self, host, username, password, domain, use_ssl=False, port=None, timeout=10):
        self.host, self.username, self.password, self.domain = host, username, password, domain
        self.use_ssl = use_ssl
        self.port = port or (636 if use_ssl else 389)
        self.timeout = timeout

    def preflight(self):
        """Validate credentials and discover naming contexts without enumeration."""
        server = Server(self.host, port=self.port, use_ssl=self.use_ssl, get_info=None, connect_timeout=self.timeout)
        user = f"{self.domain}\\{self.username}" if self.domain else self.username
        conn = Connection(server, user=user, password=self.password, authentication=NTLM,
                          auto_bind=True, raise_exceptions=True)
        conn.search("", "(objectClass=*)", search_scope="BASE",
                    attributes=["defaultNamingContext", "configurationNamingContext"])
        values = conn.entries[0].entry_attributes_as_dict
        root = values["defaultNamingContext"][0]
        config = values["configurationNamingContext"][0]
        conn.unbind()
        return root, config

    def collect(self):
        server = Server(self.host, port=self.port, use_ssl=self.use_ssl, get_info=None, connect_timeout=self.timeout)
        user = f"{self.domain}\\{self.username}" if self.domain else self.username
        conn = Connection(server, user=user, password=self.password,
                          authentication=NTLM, auto_bind=True, raise_exceptions=True)
        conn.search("", "(objectClass=*)", search_scope="BASE",
                    attributes=["defaultNamingContext", "configurationNamingContext", "minPwdLength",
                                "pwdHistoryLength", "maxPwdAge", "minPwdAge", "lockoutThreshold",
                                "lockoutDuration", "lockoutObservationWindow", "pwdProperties"])
        root_entry = conn.entries[0].entry_attributes_as_dict
        root = root_entry["defaultNamingContext"][0]
        config = root_entry["configurationNamingContext"][0]
        policy_attrs = ["minPwdLength", "pwdHistoryLength", "maxPwdAge", "minPwdAge",
                        "lockoutThreshold", "lockoutDuration", "lockoutObservationWindow", "pwdProperties"]
        conn.search(root, "(objectClass=domainDNS)", search_scope="BASE", attributes=policy_attrs)
        domain_policy = conn.entries[0].entry_attributes_as_dict if conn.entries else {}
        base = f"CN=Public Key Services,CN=Services,{config}"
        attrs_ca = ["cn", "dNSHostName", "certificateTemplates", "cACertificate", "flags", "nTSecurityDescriptor"]
        conn.search(f"CN=Enrollment Services,{base}", "(objectClass=pKIEnrollmentService)", attributes=attrs_ca, controls=security_descriptor_control(sdflags=0x04))
        raw_cas = [dict(e.entry_attributes_as_dict, distinguishedName=e.entry_dn) for e in conn.entries]
        conn.search(root, "(|(objectClass=user)(objectClass=group)(objectClass=computer))", attributes=["objectSid", "sAMAccountName", "displayName", "description", "dNSHostName", "userAccountControl", "memberOf", "member", "objectClass", "objectGUID", "primaryGroupID", "lastLogonTimestamp", "pwdLastSet"])
        raw_identities = [dict(e.entry_attributes_as_dict, distinguishedName=e.entry_dn) for e in conn.entries]
        conn.search(f"CN=Certificate Templates,{base}", "(objectClass=pKICertificateTemplate)", search_scope="LEVEL",
                    attributes=["cn", "displayName", "objectGUID", "objectSid", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
                                "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy", "msPKI-RA-Signature", "nTSecurityDescriptor"],
                    controls=security_descriptor_control(sdflags=0x04))
        raw_templates = [dict(e.entry_attributes_as_dict, distinguishedName=e.entry_dn) for e in conn.entries]
        conn.unbind()
        self.raw = {"defaultNamingContext": root, "configurationNamingContext": config,
                    "passwordPolicy": {k: domain_policy[k][0] for k in policy_attrs if k in domain_policy and domain_policy[k]},
                    "cas": raw_cas, "templates": raw_templates, "identities": raw_identities}
        return normalize_directory(self.raw)
