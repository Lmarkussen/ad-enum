"""Read-only GPO metadata and targeted SYSVOL credential-exposure parsing."""
import hashlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path

TARGET_FILES = {"groups.xml", "services.xml", "scheduledtasks.xml", "scheduledtasksv2.xml",
                "drives.xml", "datasources.xml", "printers.xml", "shortcuts.xml"}
SCRIPT_SUFFIXES = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".ini", ".xml", ".config", ".txt"}


def normalize_gpos(rows):
    result = []
    for row in rows or []:
        if not isinstance(row, dict): continue
        def first(name):
            value = row.get(name, "")
            return value[0] if isinstance(value, list) and value else value
        result.append({"guid": str(first("name") or first("objectGUID")),
                       "display_name": first("displayName"), "dn": row.get("distinguishedName", ""),
                       "sysvol_path": first("gPCFileSysPath"), "version": first("versionNumber"),
                       "flags": first("flags"), "wmi_filter": first("gPCWQLFilter")})
    return result


def _credential_signals(text):
    patterns = [
        r"(?im)\b(?:password|passwd|pwd)\s*[:=]\s*(['\"]?)[^\s'\"]+\1",
        r"(?im)\bnet\s+use\b[^\n]*\s/(?:user|u):[^\s]+\s+[^\s]+",
        r"(?im)\bcmdkey\b[^\n]*\s/(?:pass|password):[^\s]+",
        r"(?im)\b(?:connectionstring|connection-string)\s*=\s*[^\n]*(?:password|pwd)\s*=\s*[^;\s]+",
        r"(?im)convertto-securestring[^\n]*-asplaintext",
    ]
    return [pattern for pattern in patterns if re.search(pattern, text or "")]


def inspect_file(gpo, relative_path, content):
    """Return high-confidence credential findings with discovered values.

    This intentionally applies only to target data.  Scanner authentication
    credentials are never passed to this parser or persisted by it.
    """
    text = content.decode("utf-8", "replace") if isinstance(content, bytes) else str(content or "")
    lower = relative_path.lower()
    findings = []
    cpassword = re.search(r"(?i)cpassword\s*=\s*[\"']?([^\"'\s<]+)", text)
    if cpassword:
        findings.append({"rule": "gpp-cpassword", "title": f"GPP credential exposure — {gpo.get('display_name') or gpo.get('guid')}",
                         "gpo": gpo, "file": relative_path, "account": _account(text),
                         "evidence": {"type": "cpassword", "value": cpassword.group(1),
                                      "fingerprint": hashlib.sha256(text.encode()).hexdigest()[:16]}})
    signals = _credential_signals(text)
    extracted = _extract_credentials(text)
    if signals and not cpassword:
        findings.append({"rule": "gpo-cleartext-credential", "title": f"Cleartext credential in GPO — {gpo.get('display_name') or gpo.get('guid')}",
                         "gpo": gpo, "file": relative_path, "account": extracted.get("username") or _account(text),
                         "evidence": {"type": extracted.get("type", "credential-pattern"), "signals": signals,
                                      "username": extracted.get("username", "UNKNOWN"),
                                      "value": extracted.get("value"), "fingerprint": hashlib.sha256(text.encode()).hexdigest()[:16]}})
    return findings


def _extract_credentials(text):
    """Extract only explicit value-bearing credential structures."""
    patterns = [
        (r"(?im)\bnet\s+use\b[^\n]*\s/(?:user|u):([^\s]+)\s+([^\s]+)", "net use"),
        (r"(?im)\bcmdkey\b[^\n]*\s/(?:user|u):([^\s]+)[^\n]*\s/(?:pass|password):([^\s]+)", "cmdkey"),
        (r"(?im)(?:user(?:name)?|account)\s*[:=]\s*[\"']?([^\"'\s]+)[\"']?[^\n]*(?:password|passwd|pwd)\s*[:=]\s*[\"']?([^\"'\s]+)", "credential literal"),
        (r"(?im)(?:user(?:name)?|user\s*id)\s*=\s*([^;\s]+);\s*password\s*=\s*([^;\s]+)", "connection string"),
    ]
    for pattern, kind in patterns:
        match = re.search(pattern, text or "")
        if match:
            return {"type": kind, "username": match.group(1), "value": match.group(2)}
    return {"type": "credential-pattern", "username": _account(text), "value": None}


def _account(text):
    match = re.search(r"(?im)(?:user(?:name)?|account)\s*[:=]\s*[\"']?([A-Za-z0-9_.\\$-]+)", text or "")
    return match.group(1) if match else "unknown"


def collect_sysvol(context, gpos, max_bytes=1024 * 1024):
    """Read only known policy files from SYSVOL using Impacket SMB."""
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError as exc:
        return {"status": "UNAVAILABLE", "files": [], "error": f"impacket unavailable: {exc}"}
    host = context.dc_hostname or context.dc_ip
    connection = None
    files = []
    try:
        connection = SMBConnection(host, context.dc_ip, sess_port=445, timeout=context.timeout)
        connection.login(context.auth.username, context.auth.password, context.auth.domain)
        for gpo in gpos:
            guid = gpo.get("guid", "").strip("{}").upper()
            if not guid: continue
            base = "\\\\" + context.domain + "\\Policies\\{" + guid + "}"
            pending = [(base, 0)]
            discovered = []
            while pending:
                directory, depth = pending.pop()
                if depth > 5: continue
                try: entries = connection.listPath("SYSVOL", directory + "\\*")
                except Exception: continue
                for entry in entries:
                    name = entry.get_longname()
                    if name in {".", ".."}: continue
                    path = directory + "\\" + name
                    if entry.is_directory(): pending.append((path, depth + 1)); continue
                    if name.lower() in TARGET_FILES or Path(name).suffix.lower() in SCRIPT_SUFFIXES:
                        discovered.append((name, path))
            for name, path in discovered:
                data = bytearray()
                try:
                    connection.getFile("SYSVOL", path, lambda chunk: data.extend(chunk) if len(data) < max_bytes else None)
                except Exception:
                    continue
                files.append({"gpo_guid": gpo.get("guid"), "path": path, "name": name,
                              "content": bytes(data[:max_bytes])})
        return {"status": "PASS", "files": files}
    except Exception as exc:
        return {"status": "FAILED", "files": files, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        if connection is not None:
            try: connection.logoff()
            except Exception: pass


def collect_netlogon(context, max_depth=3):
    """Inventory only likely domain script/config files in NETLOGON."""
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError as exc:
        return {"status": "UNAVAILABLE", "files": [], "error": f"impacket unavailable: {exc}"}
    connection = None; files = []
    try:
        host = context.dc_hostname or context.dc_ip
        connection = SMBConnection(host, context.dc_ip, sess_port=445, timeout=context.timeout)
        connection.login(context.auth.username, context.auth.password, context.auth.domain)
        pending = [("\\*", 0)]
        while pending:
            directory, depth = pending.pop()
            if depth > max_depth: continue
            try: entries = connection.listPath("NETLOGON", directory)
            except Exception: continue
            for entry in entries:
                name = entry.get_longname()
                if name in {".", ".."}: continue
                path = directory.rstrip("*") + name
                if entry.is_directory(): pending.append((path + "\\*", depth + 1)); continue
                if Path(name).suffix.lower() in SCRIPT_SUFFIXES:
                    files.append({"path": path, "name": name, "size": entry.get_filesize()})
        return {"status": "PASS", "files": files}
    except Exception as exc:
        return {"status": "FAILED", "files": files, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        if connection is not None:
            try: connection.logoff()
            except Exception: pass
