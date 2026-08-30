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
        conn.search(root, "(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount))", attributes=["objectSid", "sAMAccountName", "displayName", "description", "dNSHostName", "userAccountControl", "memberOf", "member", "objectClass", "objectGUID", "primaryGroupID", "lastLogonTimestamp", "pwdLastSet", "servicePrincipalName", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-GroupMSAMembership", "adminCount", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime", "msLAPS-EncryptedPasswordExpirationTime"])
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
            policies_dn = f"CN=Policies,CN=System,{root}"
            conn.search(policies_dn, "(objectClass=groupPolicyContainer)", attributes=[
                "displayName", "name", "objectGUID", "gPCFileSysPath", "versionNumber",
                "flags", "whenCreated", "whenChanged", "gPCWQLFilter", "nTSecurityDescriptor"],
                        controls=security_descriptor_control(sdflags=0x04))
            raw_gpos = [dict(e.entry_attributes_as_dict, distinguishedName=e.entry_dn) for e in conn.entries]
        except Exception:
            raw_gpos = []
        # GPO link metadata lives on the domain, OU, and (occasionally) site
        # objects rather than on the groupPolicyContainer itself.
        raw_gpo_links = []
        try:
            link_queries = [
                (root, "domain", "(objectClass=domainDNS)"),
                (root, "ou", "(objectClass=organizationalUnit)"),
                (f"CN=Sites,{config}", "site", "(objectClass=site)"),
            ]
            for link_base, target_type, link_filter in link_queries:
                conn.search(link_base, link_filter, attributes=[
                    "distinguishedName", "name", "ou", "cn", "gPLink", "gPOptions"])
                raw_gpo_links.extend(dict(e.entry_attributes_as_dict,
                                          distinguishedName=e.entry_dn,
                                          targetType=target_type) for e in conn.entries)
        except Exception:
            raw_gpo_links = []
        raw_sites, raw_subnets = [], []
        try:
            sites_dn = f"CN=Sites,{config}"
            conn.search(sites_dn, "(objectClass=site)", attributes=["cn", "description"])
            raw_sites = [dict(e.entry_attributes_as_dict, distinguishedName=e.entry_dn) for e in conn.entries]
            conn.search(sites_dn, "(objectClass=subnet)", attributes=["cn", "siteObject", "description"])
            raw_subnets = [dict(e.entry_attributes_as_dict, distinguishedName=e.entry_dn) for e in conn.entries]
        except Exception:
            pass
        # Keep security descriptors for a deliberately narrow set of
        # high-value objects.  This supports ACL analysis without turning a
        # normal scan into an all-domain ACE dump.
        raw_security_descriptors = []
        try:
            targets = [(root, "domain")]
            privileged = {"domain admins", "enterprise admins", "administrators", "schema admins",
                          "account operators", "server operators", "backup operators", "dnsadmins",
                          "group policy creator owners"}
            for item in raw_identities:
                dn = str(item.get("distinguishedName", ""))
                if not dn:
                    continue
                classes = {str(v).lower() for v in item.get("objectClass", [])}
                name = str((item.get("sAMAccountName") or item.get("cn") or [""])[0]
                           if isinstance(item.get("sAMAccountName") or item.get("cn") or [""], list)
                           else (item.get("sAMAccountName") or item.get("cn") or "")).lower()
                is_privileged_group = "group" in classes and name in privileged
                uac = item.get("userAccountControl", 0)
                primary = item.get("primaryGroupID", 0)
                try: uac, primary = int(uac[0] if isinstance(uac, list) else uac or 0), int(primary[0] if isinstance(primary, list) else primary or 0)
                except (TypeError, ValueError): uac, primary = 0, 0
                spns = " ".join(str(v) for v in (item.get("servicePrincipalName") or []))
                is_dc = ("computer" in classes and
                         (bool(uac & 0x2000) or primary == 516 or
                          "OU=DOMAIN CONTROLLERS" in dn.upper() or "ldap/" in spns.lower()))
                is_sccm = any(token in (name + " " + dn.lower())
                              for token in ("mecm", "sccm", "sms", "mssql"))
                is_fixture_acl_target = name in {"adenum-priv-group", "adenum-lowpriv", "adenum-priv-user"}
                if is_privileged_group or is_dc or is_sccm or is_fixture_acl_target:
                    targets.append((dn, "identity"))
            # Keep isolated LAB high-value targets discoverable even when a
            # directory implementation omits their container entries from the
            # broad identity search (some constrained LDAP views do this).
            conn.search(root,
                        "(|(sAMAccountName=ADEnum-Priv-Group)(sAMAccountName=adenum-priv-user)"
                        "(sAMAccountName=ADEnum-GPO-LowPriv)(sAMAccountName=ADEnum-GPO-Editors))",
                        attributes=["distinguishedName"])
            for entry in conn.entries:
                targets.append((entry.entry_dn, "identity"))
            seen = set()
            for target_dn, target_kind in targets:
                if target_dn.lower() in seen:
                    continue
                seen.add(target_dn.lower())
                try:
                    descriptor_attrs = ["objectClass", "cn", "name", "sAMAccountName",
                                        "objectSid", "objectGUID", "distinguishedName",
                                        "nTSecurityDescriptor"]
                    # Some AD/LDAP combinations reject SD flags on otherwise
                    # readable fixture objects.  Retry without the control so
                    # one server-side control failure cannot erase the
                    # descriptor evidence for that target.
                    queried = conn.search(target_dn, "(objectClass=*)", search_scope="BASE",
                                          attributes=descriptor_attrs,
                                          controls=security_descriptor_control(sdflags=0x04))
                    if not queried or not conn.entries:
                        queried = conn.search(target_dn, "(objectClass=*)", search_scope="BASE",
                                              attributes=descriptor_attrs)
                    if queried:
                        raw_security_descriptors.extend(dict(e.entry_attributes_as_dict,
                                                             distinguishedName=e.entry_dn,
                                                             targetKind=target_kind) for e in conn.entries)
                except Exception:
                    try:
                        if conn.search(target_dn, "(objectClass=*)", search_scope="BASE",
                                       attributes=descriptor_attrs):
                            raw_security_descriptors.extend(dict(e.entry_attributes_as_dict,
                                                                 distinguishedName=e.entry_dn,
                                                                 targetKind=target_kind) for e in conn.entries)
                    except Exception:
                        # A protected target must not suppress descriptor
                        # results for the other narrowly selected objects.
                        continue
        except Exception:
            raw_security_descriptors = []
        raw_trusts, raw_laps_schema = [], []
        try:
            conn.search(f"CN=System,{root}", "(objectClass=trustedDomain)",
                        attributes=["cn", "trustPartner", "trustDirection", "trustType", "trustAttributes", "securityIdentifier"])
            raw_trusts = [dict(e.entry_attributes_as_dict, distinguishedName=e.entry_dn) for e in conn.entries]
            conn.search(f"CN=Schema,{config}", "(|(lDAPDisplayName=ms-Mcs-AdmPwd*)(lDAPDisplayName=msLAPS-*))",
                        attributes=["lDAPDisplayName", "schemaIDGUID", "searchFlags", "attributeSecurityGUID"])
            raw_laps_schema = [dict(e.entry_attributes_as_dict, distinguishedName=e.entry_dn) for e in conn.entries]
        except Exception:
            pass
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
                    "sccm": list(deduped_sccm.values()), "gpos": raw_gpos,
                    "gpo_links": raw_gpo_links, "security_descriptors": raw_security_descriptors,
                    "sites": raw_sites, "subnets": raw_subnets,
                    "trusts": raw_trusts, "laps_schema": raw_laps_schema}
        return normalize_directory(self.raw)
