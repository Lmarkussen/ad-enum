"""Translate common Kerberos failures into actionable operator messages."""
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class KerberosFailure:
    category: str
    message: str
    hint: str = ""
    raw: str = ""


def format_skew(seconds):
    seconds = abs(float(seconds))
    if seconds < 60:
        return f"{round(seconds):.0f}s"
    minutes, sec = divmod(round(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {sec}s"
    hours, minutes = divmod(minutes, 60)
    if minutes >= 30:
        return f"~{hours + 1}h"
    return f"~{hours}h" if not minutes else f"{hours}h {minutes}m"


def translate_kerberos_error(error):
    raw = str(error)
    text = raw.lower()
    if "krb_ap_err_skew" in text or "clock skew" in text or "clock difference" in text:
        match = re.search(r"(?:skew|offset|difference)[^0-9-]*([0-9]+(?:\.[0-9]+)?)", text)
        detail = f"Client/DC clock difference is too large: {format_skew(match.group(1))}" if match else "Client/DC clock difference is too large"
        return KerberosFailure("clock-skew", detail, "Use --sync-time.", raw)
    if any(x in text for x in ("cannot contact any kdc", "kdc unreachable", "no kdc", "network is unreachable", "connection refused")):
        return KerberosFailure("kdc-unreachable", "Kerberos cannot contact the KDC", "Check -domain, -dc-ip, DNS, and --auto-config.", raw)
    if any(x in text for x in ("unknown principal", "principal unknown", "client not found", "realm not found", "krb5_kdc_err_c_principal_unknown", "server not found in kerberos database")):
        return KerberosFailure("principal-or-realm", "The Kerberos principal or realm was not found", "Check the username, domain, and DC hostname.", raw)
    if any(x in text for x in ("preauthentication failed", "pre-authentication failed", "kdc_err_preauth_failed", "password incorrect", "wrong password")):
        return KerberosFailure("bad-credentials", "Credentials Invalid", "", raw)
    if any(x in text for x in ("ticket expired", "ticket not yet valid", "kdc_err_expired", "kdc_err_ticket_expired")):
        return KerberosFailure("ticket-validity", "The Kerberos ticket or cache is expired or not yet valid", "Check the cache and client/DC time.", raw)
    if any(x in text for x in ("cannot resolve", "name or service not known", "getaddrinfo", "server not found")):
        return KerberosFailure("dns-or-spn", "Kerberos could not resolve the DC hostname", "Try --auto-config or verify DNS and the DC hostname.", raw)
    return KerberosFailure("unknown", "Kerberos authentication failed", "Re-run with --verbose for protocol details.", raw)
