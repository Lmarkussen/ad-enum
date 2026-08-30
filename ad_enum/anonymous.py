"""Bounded anonymous LDAP and SMB posture probes.

These probes intentionally collect only protocol posture and small metadata
sets.  They never enumerate credentials, hashes, or arbitrary shares.
"""
from ldap3 import ANONYMOUS, BASE, SUBTREE, Connection, Server


def probe_anonymous_ldap(host, domain, *, port=389, timeout=5):
    result = {"host": host, "port": port, "bind": "ERROR", "rootdse": "ERROR",
              "domain_data": "ERROR", "sources": ["native-anonymous-ldap"]}
    try:
        server = Server(host, port=port, connect_timeout=timeout, get_info=None)
        conn = Connection(server, authentication=ANONYMOUS, receive_timeout=timeout,
                          auto_bind=True, raise_exceptions=True)
        result["bind"] = "ACCEPTED"
        rootdse_ok = conn.search("", "(objectClass=*)", search_scope=BASE,
                                 attributes=["defaultNamingContext", "namingContexts"], size_limit=1)
        result["rootdse"] = "READABLE" if rootdse_ok else "DENIED"
        naming = "DC=" + ",DC=".join(str(domain).split("."))
        contexts = conn.entries[0].entry_attributes_as_dict.get("defaultNamingContext", []) if conn.entries else []
        if contexts:
            naming = contexts[0] if isinstance(contexts, list) else contexts
        found = conn.search(naming, "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
                            search_scope=SUBTREE, attributes=["distinguishedName"], size_limit=5)
        result["domain_data"] = "READABLE" if found and conn.entries else "DENIED"
        result["sample_count"] = min(len(conn.entries), 5)
        conn.unbind()
    except Exception as exc:
        result["error"] = type(exc).__name__
        if result["bind"] == "ERROR": result["bind"] = "DENIED"
        if result["rootdse"] == "ERROR": result["rootdse"] = "DENIED"
        if result["domain_data"] == "ERROR": result["domain_data"] = "DENIED"
    return result


def probe_anonymous_smb(host, ip=None, *, port=445, timeout=5):
    result = {"host": host, "ip": ip or host, "port": port,
              "session": "UNKNOWN", "share_enumeration": "UNKNOWN", "shares": [],
              "sources": ["impacket-anonymous-smb"]}
    try:
        from impacket.smbconnection import SMBConnection
        conn = SMBConnection(host, ip or host, sess_port=port, timeout=timeout)
        conn.login("", "")
        result["session"] = "SESSION_ACCEPTED"
        try:
            shares = conn.listShares()
            result["shares"] = [str(share["shi1_netname"]).rstrip("\x00") for share in shares]
            result["share_enumeration"] = "SHARE_ENUM_ALLOWED"
        except Exception as exc:
            result["share_enumeration"] = "DENIED"
            result["error"] = type(exc).__name__
        conn.logoff()
    except Exception as exc:
        result["session"] = "DENIED" if "STATUS_ACCESS_DENIED" in str(exc).upper() else "UNKNOWN"
        result["share_enumeration"] = "DENIED" if result["session"] == "DENIED" else "UNKNOWN"
        result["error"] = type(exc).__name__
    return result
