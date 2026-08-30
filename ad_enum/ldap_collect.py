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

    def _kerberos_env(self):
        if not self.domain:
            raise RuntimeError("Kerberos requires a DNS domain")
        dc_host = socket.getfqdn(self.host)
        kdc_address = self.host if re.match(r"^\d+(?:\.\d+){3}$", self.host) else dc_host
        principal = f"{self.username}@{self.domain.upper()}"
        ccache = tempfile.NamedTemporaryFile(prefix="ad-enum-", suffix=".ccache", delete=False)
        ccache.close()
        krb5 = tempfile.NamedTemporaryFile(prefix="ad-enum-", suffix=".krb5.conf", mode="w", delete=False)
        krb5.write("[libdefaults]\n default_realm = %s\n dns_lookup_kdc = false\n rdns = false\n\n[realms]\n %s = {\n  kdc = %s\n  admin_server = %s\n }\n\n[domain_realm]\n .%s = %s\n %s = %s\n" %
                    (self.domain.upper(), self.domain.upper(), kdc_address, kdc_address,
                     self.domain.lower(), self.domain.upper(), self.domain.lower(), self.domain.upper()))
        krb5.close()
        try:
            kinit = shutil.which("kinit") or "/usr/bin/kinit"
            kinit_env = os.environ.copy(); kinit_env["KRB5_CONFIG"] = krb5.name
            proc = subprocess.run([kinit, "-c", ccache.name, principal], input=self.password + "\n",
                                  text=True, capture_output=True, timeout=self.timeout, check=False, env=kinit_env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            os.unlink(ccache.name); os.unlink(krb5.name)
            raise RuntimeError(f"Kerberos credential preflight failed: {exc}") from exc
        if proc.returncode:
            os.unlink(ccache.name); os.unlink(krb5.name)
            raise RuntimeError(f"Kerberos credential preflight failed: {proc.stderr[-300:]}")
        return ccache.name, {"KRB5CCNAME": ccache.name, "KRB5_CONFIG": krb5.name, "AD_ENUM_DC_HOST": dc_host}, krb5.name

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
        return conn, (path, previous, krb5_path, previous_config)

    @staticmethod
    def _close(conn, kerberos_state):
        conn.unbind()
        if kerberos_state:
            path, previous, krb5_path, previous_config = kerberos_state
            if previous: os.environ["KRB5CCNAME"] = previous
            else: os.environ.pop("KRB5CCNAME", None)
            if previous_config: os.environ["KRB5_CONFIG"] = previous_config
            else: os.environ.pop("KRB5_CONFIG", None)
            try: os.unlink(path)
            except FileNotFoundError: pass
            try: os.unlink(krb5_path)
            except FileNotFoundError: pass

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
        conn.search(f"CN=Certificate Templates,{base}", "(objectClass=pKICertificateTemplate)", search_scope="LEVEL",
                    attributes=["cn", "displayName", "objectGUID", "objectSid", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
                                "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy", "msPKI-RA-Signature", "nTSecurityDescriptor"],
                    controls=security_descriptor_control(sdflags=0x04))
        raw_templates = [dict(e.entry_attributes_as_dict, distinguishedName=e.entry_dn) for e in conn.entries]
        self._close(conn, state)
        self.raw = {"defaultNamingContext": root, "configurationNamingContext": config,
                    "passwordPolicy": {k: domain_policy[k][0] for k in policy_attrs if k in domain_policy and domain_policy[k]},
                    "cas": raw_cas, "templates": raw_templates, "identities": raw_identities}
        return normalize_directory(self.raw)
