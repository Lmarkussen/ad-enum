from ldap3 import NTLM, SASL, GSSAPI, Connection, Server
import os
import subprocess
import tempfile
import socket
import shutil
import re
from ldap3.protocol.microsoft import security_descriptor_control
from .models import CA, Template
from .security import parse_security_descriptor_safe
from .rights import effective_enrollment, derive_template_rights
from .identity import Resolver
from .normalize import normalize_directory
from .core.kerberos_session import KerberosSession


def _value(entry, key, default=None):
    value = entry.entry_attributes_as_dict.get(key, default)
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


class Collector:
    def __init__(self, host, username, password, domain, use_ssl=False, port=None, timeout=10, force_kerb=False):
        self.host, self.username, self.password, self.domain = host, username, password, domain
        self.use_ssl = use_ssl
        self.port = port or (636 if use_ssl else 389)
        self.timeout = timeout
        self.force_kerb = force_kerb
        self.kerberos_session = None

    def _kerberos_env(self):
        if self.kerberos_session is None:
            self.kerberos_session = KerberosSession(self.username, self.password, self.domain,
                                                    self.host, self.timeout).acquire()
        return self.kerberos_session.ccache, {"KRB5CCNAME": self.kerberos_session.ccache,
                                               "KRB5_CONFIG": self.kerberos_session.krb5_config}, None

    def _connection(self):
        server_host = socket.getfqdn(self.host) if self.force_kerb else self.host
        server = Server(server_host, port=self.port, use_ssl=self.use_ssl, get_info=None, connect_timeout=self.timeout)
        if not self.force_kerb:
            user = f"{self.domain}\\{self.username}" if self.domain else self.username
            return Connection(server, user=user, password=self.password, authentication=NTLM,
                              auto_bind=True, raise_exceptions=True), None
        path, env, krb5_path = self._kerberos_env()
        previous = os.environ.get("KRB5CCNAME")
        previous_config = os.environ.get("KRB5_CONFIG")
        os.environ.update(env)
        try:
            conn = Connection(server, user=f"{self.username}@{self.domain.upper()}",
                              authentication=SASL, sasl_mechanism=GSSAPI,
                              auto_bind=True, raise_exceptions=True)
        except Exception:
            os.environ.pop("KRB5CCNAME", None)
            if previous: os.environ["KRB5CCNAME"] = previous
            if previous_config: os.environ["KRB5_CONFIG"] = previous_config
            else: os.environ.pop("KRB5_CONFIG", None)
            os.unlink(path); os.unlink(krb5_path)
            raise
        return conn, ("session", self.kerberos_session)

    @staticmethod
    def _close(conn, kerberos_state):
        conn.unbind()
        # Keep the session active so compatible subprocess adapters reuse it.

    def preflight(self):
        """Validate credentials and discover naming contexts without enumeration."""
        conn, state = self._connection()
        conn.search("", "(objectClass=*)", search_scope="BASE",
                    attributes=["defaultNamingContext", "configurationNamingContext"])
        values = conn.entries[0].entry_attributes_as_dict
        root = values["defaultNamingContext"][0]
        config = values["configurationNamingContext"][0]
        self._close(conn, state)
        return root, config

    def collect(self):
        conn, state = self._connection()
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
        conn.search(root, "(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount))", attributes=["objectSid", "sAMAccountName", "displayName", "description", "dNSHostName", "userAccountControl", "memberOf", "member", "objectClass", "objectGUID", "primaryGroupID", "lastLogonTimestamp", "pwdLastSet", "servicePrincipalName", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-GroupMSAMembership", "adminCount"])
        raw_identities = [dict(e.entry_attributes_as_dict, distinguishedName=e.entry_dn) for e in conn.entries]
        # SCCM publishes site/service metadata below this AD container when
        # the System Management publication is enabled.  Collection is
        # best-effort: absence is meaningful and must not break AD scans.
        system_management = f"CN=System Management,CN=System,{root}"
        sccm_attrs = ["objectClass", "cn", "name", "displayName", "keywords",
                      "serviceBindingInformation", "serviceDNSName", "dNSHostName",
                      "mSSMS-Assignment-Site-Code", "mSSMS-Default-Management-Point",
                      "mSSMS-Default-Management-Point-Name", "mSSMS-Device-Management-Point",
                      "mSSMS-Site-Code", "mSSMS-Site-System-Roles", "mSSMS-Version",
                      "netbootSCPBL", "netbootAnswer", "netbootSCP"]
        raw_sccm = []
        try:
            conn.search(system_management, "(objectClass=*)", attributes=sccm_attrs)
            raw_sccm = [dict(e.entry_attributes_as_dict, distinguishedName=e.entry_dn) for e in conn.entries]
        except Exception:
            raw_sccm = []
        try:
            conn.search(root, "(objectClass=serviceConnectionPoint)", attributes=sccm_attrs)
            raw_sccm.extend(dict(e.entry_attributes_as_dict, distinguishedName=e.entry_dn) for e in conn.entries)
        except Exception:
            pass
        # Group Policy objects live in the Configuration NC; collect metadata
        # only. SYSVOL file inspection is performed separately by the GPO
        # module so LDAP collection remains transport-focused.
        raw_gpos = []
        try:
            policies_dn = f"CN=Policies,CN=System,{config}"
            conn.search(policies_dn, "(objectClass=groupPolicyContainer)", attributes=[
                "displayName", "name", "objectGUID", "gPCFileSysPath", "versionNumber",
                "flags", "whenCreated", "whenChanged", "gPCWQLFilter"])
            raw_gpos = [dict(e.entry_attributes_as_dict, distinguishedName=e.entry_dn) for e in conn.entries]
        except Exception:
            raw_gpos = []
        conn.search(f"CN=Certificate Templates,{base}", "(objectClass=pKICertificateTemplate)", search_scope="LEVEL",
                    attributes=["cn", "displayName", "objectGUID", "objectSid", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
                                "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy", "msPKI-RA-Signature", "nTSecurityDescriptor"],
                    controls=security_descriptor_control(sdflags=0x04))
        raw_templates = [dict(e.entry_attributes_as_dict, distinguishedName=e.entry_dn) for e in conn.entries]
        self._close(conn, state)
        # The System Management subtree and the serviceConnectionPoint search
        # overlap on real domains. Keep one LDAP-shaped record per DN so
        # downstream provenance/counts are deterministic.
        deduped_sccm = {}
        for item in raw_sccm:
            dn = str(item.get("distinguishedName", ""))
            deduped_sccm[dn.lower()] = item
        self.raw = {"defaultNamingContext": root, "configurationNamingContext": config,
                    "passwordPolicy": {k: domain_policy[k][0] for k in policy_attrs if k in domain_policy and domain_policy[k]},
                    "cas": raw_cas, "templates": raw_templates, "identities": raw_identities,
                    "sccm": list(deduped_sccm.values()), "gpos": raw_gpos}
        return normalize_directory(self.raw)
