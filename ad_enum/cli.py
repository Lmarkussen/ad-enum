import argparse
import hashlib
import sys
import ipaddress
import re
import shutil
import socket
import textwrap
from importlib.resources import files
from .ldap_collect import Collector
from .adcs import scan
from .adapters.certipy import CertipyAdapter
from .core.workspace import ScanWorkspace, canonical_domain
from .core.autoconfig import inspect as inspect_autoconfig, sync_time as sync_clock
from .core.kerberos_errors import translate_kerberos_error
from .core.context import AuthContext, ScanContext
from .core.planner import ExecutionPlanner
from .core.findings import NormalizedFinding
from .external import execute_external
from .inventory import (native_inventory, DomainInventory, build_targets, sensitive_description,
                        parse_netexec_smb, extract_attribute_secret, is_standard_admin_share)
from .sccm import (discover as discover_sccm, normalize_relayking,
                   probe_management_points, cred1_candidates)
from .network import build_dns_map
from .dns_enum import normalize_zones, normalize_records, merge_into_dns_map, normalize_password_settings
from .gpo import normalize_gpos, collect_sysvol, collect_netlogon, inspect_file, parse_security_settings
from .posture import (normalize_smb, normalize_trusts, normalize_gpo_acls, normalize_laps,
                      attach_gpo_links, normalize_security_descriptors, analyze_effective_acls)
from .kerberos import roastable, account_exposure, privileged_account_sids, account_security_context
from .delegation import enumerate_delegation, enumerate_gmsa
from .core.console import Console
from .core.coverage import CoverageReport
from .anonymous import probe_anonymous_ldap, probe_anonymous_smb
from .reporting.html import write_html_report
from .recon import (normalize_mssql, normalize_dfs, normalize_services,
                    normalize_trust_context, build_privilege_paths, correlate_dfs_targets)
from .service_probe import DEFAULT_SERVICES, probe_known_services
from .access import from_netexec_hosts, merge_access, filter_redundant_access_targets
from .adapters.netexec import NetExecAdapter
from .cinderpath_adapter import run_cinderpath_cred1, cinderpath_path
from .cred1_runtime import check_cred1_runtime, fix_cinderpath_capabilities


CATEGORY_ORDER = ("ADCS", "POLICY", "KERBEROS", "ACCOUNT", "DELEGATION",
                  "GPO", "ACL", "LAPS", "LDAP", "SMB", "RELAY", "SCCM", "TRUSTS")


def _compact_field_lines(fields, *, indent="  ", width=None, max_label_width=20):
    """Render aligned field/value rows with wrapped value continuations."""
    fields = [(str(label), "" if value is None else str(value)) for label, value in fields]
    if not fields:
        return []
    label_width = min(max(len(label) for label, _ in fields), max_label_width)
    terminal_width = width or shutil.get_terminal_size((100, 24)).columns
    prefix_width = len(indent) + label_width + 2
    value_width = max(12, terminal_width - prefix_width)
    continuation = " " * prefix_width
    lines = []
    for label, value in fields:
        chunks = []
        for paragraph in value.splitlines() or [""]:
            chunks.extend(textwrap.wrap(paragraph, width=value_width, break_long_words=True,
                                        break_on_hyphens=False, replace_whitespace=False) or [""])
        lines.append(f"{indent}{label:<{label_width}}  {chunks[0]}")
        lines.extend(f"{continuation}{chunk}" for chunk in chunks[1:])
    return lines


def _cred1_summary_lines(item, *, indent="  ", width=None):
    """Render the human-readable CRED-1 summary without changing its data."""
    evidence = item or {}
    lines = _compact_field_lines([
        ("Distribution Point", evidence.get("dp", "unknown")),
        ("Site", evidence.get("site_code", "UNKNOWN")),
        ("Interface", evidence.get("interface", "UNKNOWN")),
    ], indent=indent, width=width)
    lines.extend(["", f"{indent}PXE / WDS"])
    lines.extend(_compact_field_lines([
        ("WDS reply", evidence.get("wds", "UNKNOWN")),
        ("PXE", evidence.get("pxe", "UNKNOWN")),
        ("TFTP", evidence.get("tftp", "UNKNOWN")),
        ("boot.var", evidence.get("boot_var", "UNKNOWN")),
        ("Media identity", evidence.get("media_identity", "UNKNOWN")),
        ("Assignment", evidence.get("assignment", "UNKNOWN")),
        ("Policies", evidence.get("policies", 0)),
    ], indent=indent + "  ", width=width))
    lines.extend(["", f"{indent}Inspection"])
    lines.extend(_compact_field_lines([
        ("Boot metadata", evidence.get("boot_file") or "UNKNOWN"),
        ("Media protection", evidence.get("media_protection", "UNKNOWN")),
        ("Secret inspection", evidence.get("secret_inspection", "NOT ATTEMPTED")),
        ("Unique secrets", len(evidence.get("credentials", []) or [])),
    ], indent=indent + "  ", width=width))
    credentials = evidence.get("credentials", []) or []
    if credentials:
        lines.extend(["", f"{indent}Recovered credential"])
        for index, secret in enumerate(credentials):
            if index:
                lines.append("")
            fields = [("Type", secret.get("type", "other")), ("Name", secret.get("name", ""))]
            if secret.get("username"):
                fields.append(("Username", secret["username"]))
            fields.append(("Password", secret.get("value", secret.get("password", ""))))
            if secret.get("source_policy"):
                fields.append(("Source", secret["source_policy"]))
            lines.extend(_compact_field_lines(fields, indent=indent + "  ", width=width))
    return lines


def _finding_detail_lines(item, *, indent="    ", width=None, status_override=None):
    """Render detailed finding fields while preserving existing semantics."""
    status = status_override if status_override is not None else item.get("status", "").upper()
    evidence = item.get("evidence", {}) or {}
    if item.get("rule") == "ESC1":
        fields = [("Status", status)]
        if item.get("status") in {"disagreement", "live-confirmed disagreement"}:
            fields.append(("Note", "Certipy did not classify this template as ESC1"))
        return _compact_field_lines(fields, indent=indent, width=width)
    if item.get("rule") == "Kerberoastable-account":
        fields = [("State", "enabled" if evidence.get("enabled") else "disabled"),
                  ("SPNs", len(evidence.get("spns", []))), ("Status", status)]
        for label, key in (("Privileged", "privileged"), ("Service account", "service_account"),
                           ("Password age", "password_age")):
            if key in evidence:
                fields.append((label, evidence[key]))
        return _compact_field_lines(fields, indent=indent, width=width)
    if item.get("category") == "ACL":
        return _compact_field_lines([
            ("Principal", evidence.get("principal_sid", "unknown")),
            ("Rights", evidence.get("effective_rights", "")),
            ("Impact", "Low-privileged principal can alter or control this object"),
        ], indent=indent, width=width)
    if item.get("category") == "DELEGATION" and item.get("rule") == "rbcd":
        return _compact_field_lines([
            ("Allowed principal", evidence.get("principal_name") or evidence.get("principal_sid", "unknown")),
            ("Impact", evidence.get("impact", "May impersonate users to Kerberos services on the target")),
        ], indent=indent, width=width)
    if item.get("rule", "").startswith("gpo-"):
        fields = []
        if evidence.get("file"): fields.append(("File", evidence["file"]))
        if evidence.get("account"): fields.append(("Account", evidence["account"]))
        if evidence.get("type"): fields.append(("Type", evidence["type"]))
        if evidence.get("value"):
            fields.append(("cpassword" if item.get("rule") == "gpp-cpassword" else "Value", evidence["value"]))
        return _compact_field_lines(fields, indent=indent, width=width)
    if item.get("category") == "SCCM" and item.get("rule") == "CRED-1":
        lines = _compact_field_lines([
            ("Distribution Point", evidence.get("dp", item.get("affected_object", "unknown"))),
            ("Site", evidence.get("site", "UNKNOWN")),
            ("Interface", evidence.get("interface", "UNKNOWN")),
        ], indent=indent, width=width)
        lines.extend(["", f"{indent}PXE / WDS"])
        lines.extend(_compact_field_lines([
            ("WDS reply", evidence.get("wds", "UNKNOWN")),
            ("boot.var", evidence.get("boot_var", "UNKNOWN")),
            ("Media identity", evidence.get("media_identity", "UNKNOWN")),
            ("Assignment", evidence.get("assignment", "UNKNOWN")),
            ("Policies", evidence.get("policies", 0)),
        ], indent=indent + "  ", width=width))
        lines.extend(["", f"{indent}Inspection"])
        # The CRED-1 section owns the aggregate count.  Keep the finding's
        # status here without repeating that same normalized value below it.
        lines.extend(_compact_field_lines([("Status", status)], indent=indent + "  ", width=width))
        lines.extend(["", f"{indent}Recovered credential"])
        fields = [("Type", evidence.get("type", "other")), ("Name", evidence.get("name", ""))]
        if evidence.get("username"):
            fields.append(("Username", evidence["username"]))
        fields.append(("Password", evidence.get("value", "")))
        if evidence.get("source_policy"):
            fields.append(("Source", evidence["source_policy"]))
        lines.extend(_compact_field_lines(fields, indent=indent + "  ", width=width))
        return lines
    if status.lower() in {"single-source", "corroborated"}:
        return []
    return _compact_field_lines([("Status", status)], indent=indent, width=width) if status else []


def _finding_lines(findings, *, width=None):
    """Render normalized findings without terminal decoration.

    This is deliberately also suitable for results.txt: it contains the
    operator-facing evidence, but never progress, subprocess output, or raw
    diagnostics.
    """
    grouped = {category: [] for category in CATEGORY_ORDER}
    for item in findings:
        if item.get("rule") == "Kerberoastable-account" and item.get("title", "").endswith("(disabled)"):
            continue
        grouped.setdefault(item.get("category", "OTHER"), []).append(item)
    lines = []
    for category in CATEGORY_ORDER + tuple(x for x in grouped if x not in CATEGORY_ORDER):
        items = grouped.get(category, [])
        if not items:
            continue
        # The leading empty line is part of the report contract.  The
        # previous finding already contributes the trailing empty line, so
        # do not add another one at category boundaries.
        if not lines or lines[-1] != "":
            lines.append("")
        lines.append(f"------------[ {category} ]------------")
        for item in items:
            status = item.get("status", "").upper()
            if item.get("rule") == "ESC1" and status in {"DISAGREEMENT", "LIVE-CONFIRMED DISAGREEMENT"}:
                status = "CONFIRMED"
            title = item.get("title", "")
            if category == "ACL":
                title = f"Account control — {item.get('affected_object', title)}"
            lines.append(f"  {title}")
            objects = _affected_object_values(item)
            if objects:
                lines.append("    Affected objects")
                lines.extend(f"      {value}" for value in objects)
            lines.extend(_finding_detail_lines(item, indent="    ", width=width,
                                               status_override=status))
            lines.append("")
    return lines


def _affected_object_values(item, limit=None):
    """Extract stable display identities from aggregated finding evidence."""
    evidence = item.get("evidence", {}) or {}
    values = evidence.get("affected_objects")
    if values is None:
        for key in ("hosts", "accounts", "groups", "computers", "shares", "templates", "gpos", "objects"):
            if isinstance(evidence.get(key), list):
                values = evidence[key]
                break
    if not isinstance(values, list) or len(values) <= 1:
        return []
    result = []
    for value in values:
        if isinstance(value, dict):
            value = (value.get("fqdn") or value.get("host") or value.get("name") or
                     value.get("account") or value.get("share") or value.get("dn") or value.get("ip"))
        if value not in (None, ""):
            result.append(str(value))
    result = list(dict.fromkeys(result))
    if limit is not None and len(result) > limit:
        return result[:limit] + [f"... and {len(result) - limit} more"]
    return result


def _host_parts(item):
    raw_host = item.get("host") or item.get("hostname") or item.get("name") or item.get("ip") or "unknown"
    host = str(raw_host).strip().rstrip(".")
    ip = str(item.get("ip") or "").strip()
    suffix = re.search(r"\s+\(([^()]+)\)$", host)
    if suffix:
        candidate = suffix.group(1).strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            pass
        else:
            if not ip:
                ip = candidate
            host = host[:suffix.start()].rstrip().rstrip(".")
    return host or ip or "unknown", ip


def _host_identity_index(host_identities):
    """Index existing DNS/inventory endpoint evidence for presentation only."""
    if isinstance(host_identities, dict):
        records = host_identities.get("records", [])
    else:
        records = host_identities or []
    identities, alias_candidates, ip_candidates = {}, {}, {}
    for record in records:
        if not isinstance(record, dict):
            continue
        fqdn = str(record.get("fqdn") or record.get("hostname") or "").strip().rstrip(".")
        if not fqdn or "." not in fqdn:
            continue
        identity = fqdn.casefold()
        item = identities.setdefault(identity, {"display": fqdn, "ips": set()})
        values = record.get("ip_addresses") or record.get("ips") or record.get("ip") or []
        if isinstance(values, str):
            values = [values]
        for value in values:
            value = str(value).strip()
            if value:
                item["ips"].add(value.casefold())
                ip_candidates.setdefault(value.casefold(), set()).add(identity)
        aliases = {fqdn.casefold()}
        short_name = str(record.get("short_name") or fqdn.split(".", 1)[0]).strip()
        if short_name:
            aliases.add(short_name.casefold())
        for alias in aliases:
            alias_candidates.setdefault(alias, set()).add(identity)
    return {"identities": identities, "aliases": alias_candidates, "ips": ip_candidates}


def _host_identity(item, identity_index):
    host, ip = _host_parts(item)
    aliases = identity_index["aliases"].get(host.casefold(), set())
    by_ip = identity_index["ips"].get(ip.casefold(), set()) if ip else set()
    identity = None
    if len(aliases) == 1:
        candidate = next(iter(aliases))
        known_ips = identity_index["identities"][candidate]["ips"]
        if not ip or not known_ips or ip.casefold() in known_ips:
            identity = candidate
    if identity is None and len(by_ip) == 1:
        identity = next(iter(by_ip))
    if identity is not None:
        return ("identity", identity), identity_index["identities"][identity]["display"], host, ip
    if ip:
        return ("ip", ip.casefold()), "", host, ip
    return ("host", host.casefold()), "", host, ip


def _host_groups(items, host_identities=None):
    identity_index = _host_identity_index(host_identities)
    groups = {}
    for item in items:
        key, canonical, host, ip = _host_identity(item, identity_index)
        group = groups.setdefault(key, {"canonical": canonical, "hosts": set(), "ips": set(), "items": []})
        group["hosts"].add(host)
        if ip:
            group["ips"].add(ip)
        group["items"].append(item)
    for group in groups.values():
        if not group["canonical"]:
            candidates = sorted(group["hosts"], key=lambda value: ("." not in value, value.casefold()))
            group["canonical"] = candidates[0] if candidates else sorted(group["ips"])[0]
    return groups


def _port_sort(value):
    try:
        return 0, int(value)
    except (TypeError, ValueError):
        return 1, str(value or "").casefold()


def _service_label(item):
    return f"{item.get('service') or item.get('name') or 'Service'}/{item.get('port', '')}"


def _service_summary_lines(services, limit=None, host_identities=None):
    """Render observed services grouped by canonical host, preserving states."""
    open_services = [x for x in (services or [])
                     if isinstance(x, dict) and (x.get("reachable") or x.get("state") == "OPEN")]
    open_services.sort(key=lambda x: (str(x.get("host") or x.get("ip", "")).casefold(),
                                      _port_sort(x.get("port")),
                                      str(x.get("service") or x.get("name") or "").casefold()))
    if limit is not None:
        open_services = open_services[:limit]
    groups = _host_groups(open_services, host_identities)
    rows = []
    for group in groups.values():
        unique = {}
        for item in group["items"]:
            key = (str(item.get("service") or item.get("name") or "").casefold(),
                   str(item.get("port", "")), str(item.get("transport", "")).casefold(),
                   str(item.get("protocol_state", "TCP OPEN")))
            unique.setdefault(key, item)
        group["items"] = list(unique.values())
        rows.extend((_service_label(item), item.get("protocol_state", "TCP OPEN"))
                    for item in group["items"])
    width = max((len(label) for label, _ in rows), default=0)
    lines = []
    for group in sorted(groups.values(), key=lambda value: value["canonical"].casefold()):
        if lines:
            lines.append("")
        lines.append(f"  {group['canonical']}")
        for item in sorted(group["items"], key=lambda value: (
                _port_sort(value.get("port")),
                str(value.get("service") or value.get("name") or "").casefold(),
                str(value.get("protocol_state", "TCP OPEN")).casefold())):
            label = _service_label(item)
            lines.append(f"    {label:<{width}}  {item.get('protocol_state', 'TCP OPEN')}")
    return lines


def _access_summary_lines(access_records, host_identities=None):
    """Render authenticated access grouped by endpoint without changing scope."""
    authenticated = [x for x in (access_records or [])
                     if isinstance(x, dict) and x.get("authentication") == "AUTHENTICATED"]
    groups = _host_groups(authenticated, host_identities)
    protocol_order = {name: index for index, name in enumerate(("SMB", "LDAP", "SSH", "RDP", "WINRM", "MSSQL"))}
    rows = []
    for group in groups.values():
        unique = {}
        for item in group["items"]:
            protocol = str(item.get("protocol") or "UNKNOWN").upper()
            key = (protocol, str(item.get("port", "")), str(item.get("privilege", "")).upper())
            unique.setdefault(key, item)
        group["items"] = list(unique.values())
        rows.extend((str(item.get("protocol") or "UNKNOWN").upper(), item) for item in group["items"])
    width = max((len(protocol) for protocol, _ in rows), default=0)
    lines = []
    for group in sorted(groups.values(), key=lambda value: value["canonical"].casefold()):
        if lines:
            lines.append("")
        header = f"  {group['canonical']}"
        ips = sorted(group["ips"])
        try:
            canonical_is_ip = bool(ipaddress.ip_address(group["canonical"]))
        except ValueError:
            canonical_is_ip = False
        if ips and not canonical_is_ip:
            header += f"  ({', '.join(ips)})"
        lines.append(header)
        for item in sorted(group["items"], key=lambda value: (
                protocol_order.get(str(value.get("protocol") or "UNKNOWN").upper(), len(protocol_order)),
                _port_sort(value.get("port")),
                str(value.get("protocol") or "UNKNOWN").casefold())):
            protocol = str(item.get("protocol") or "UNKNOWN").upper()
            admin = "   [ADMIN]" if str(item.get("privilege", "")).upper() == "ADMIN" else ""
            lines.append(f"    {protocol:<{width}}  AUTHENTICATED{admin}")
    return lines


def _smb_access_state(share):
    if share.get("writable"):
        return "READ / WRITE"
    if share.get("readable") is True:
        return "READ"
    if share.get("readable") is False:
        return "DENIED"
    return "UNKNOWN"


def _smb_display_name(share):
    host = share.get("host") or share.get("ip", "unknown")
    return f"{host}\\{share.get('share', 'unknown')}"


def _smb_path_is_redundant(share, display_name):
    path = share.get("unc")
    if not path:
        return False
    expected = f"\\\\{display_name}"
    normalize = lambda value: str(value).replace("/", "\\").rstrip("\\").casefold()
    return normalize(path) == normalize(expected)


def _smb_share_access_lines(shares):
    """Render the compact, grouped human-readable SMB share summary.

    This is presentation-only.  The share dictionaries, including their UNC
    paths and access flags, are not modified here.
    """
    groups = {
        "Writable non-admin shares": [],
        "Administrative shares": [],
        "Other accessible shares": [],
        "Inaccessible / denied": [],
    }
    for share in shares or []:
        state = _smb_access_state(share)
        if state in {"DENIED", "UNKNOWN"}:
            group = "Inaccessible / denied"
        elif share.get("writable") and not is_standard_admin_share(share.get("share")):
            group = "Writable non-admin shares"
        elif is_standard_admin_share(share.get("share")):
            group = "Administrative shares"
        else:
            group = "Other accessible shares"
        groups[group].append((share, state))

    entries = [item for group in groups.values() for item in group]
    width = max((len(_smb_display_name(share)) for share, _ in entries), default=0)
    lines = []
    for title, items in groups.items():
        if not items:
            continue
        if lines:
            lines.append("")
        lines.append(f"  {title}")
        for share, state in sorted(items, key=lambda item: (
                str(item[0].get("host") or item[0].get("ip", "")).casefold(),
                str(item[0].get("share", "")).casefold())):
            display_name = _smb_display_name(share)
            lines.append(f"    {display_name:<{width}}  {state}")
            if share.get("unc") and not _smb_path_is_redundant(share, display_name):
                lines.append(f"      Path ............. {share['unc']}")
    return lines


def _results_text(root, target, external_results, inventory, cas, templates, all_findings,
                  workspace, *, corroborated=0, disagreements=0, smb_shares=None, services=None,
                  access_records=None, cred1=None, host_identities=None):
    lines = ["AD-Enum", "", "Target",
             Console.field("Domain", root), Console.field("DC", target), "",
             "Collectors", Console.field("Native LDAP", "PASS")]
    for module_id, label in (("bloodhound", "BloodHound"), ("adcs-certipy", "Certipy"),
                             ("ldapdomaindump", "LDAPDomainDump"), ("netexec", "NetExec")):
        state = external_results.get(module_id, {}).get("status", "NOT CHECKED")
        display = {"PASS": "PASS", "FAILED": "FAILED", "UNAVAILABLE": "NOT AVAILABLE"}.get(state, state)
        lines.append(Console.field(label, display))
    lines.extend(["", "Inventory"])
    counts = inventory.counts()
    for key, label in (("users", "Users"), ("groups", "Groups"), ("computers", "Computers"),
                       ("domain_controllers", "Domain Controllers"), ("domains", "Domains"),
                       ("gmsa", "gMSAs")):
        lines.append(Console.field(label, counts.get(key, 0)))
    lines.extend([Console.field("CAs", len(cas)), Console.field("Templates", len(templates)), "",
                  "Correlation", Console.field("Corroborated", corroborated),
                  Console.field("Disagreements", disagreements)])
    shares = smb_shares or []
    if shares:
        lines.extend(["", "SMB Share Access", *_smb_share_access_lines(shares)])
    service_lines = _service_summary_lines(services, host_identities=host_identities)
    if service_lines:
        lines.extend(["", "Service Exposure", *service_lines])
    access_lines = _access_summary_lines(access_records, host_identities=host_identities)
    if access_lines:
        lines.extend(["", "Authenticated Access", *access_lines])
    if cred1:
        lines.extend(["", "SCCM CRED-1 PXE"])
        cred1_items = cred1 if isinstance(cred1, list) else [cred1]
        for index, item in enumerate(cred1_items):
            if index:
                lines.append("")
            lines.extend(_cred1_summary_lines(item, indent="  "))
    lines.extend(["", "Findings"])
    finding_lines = _finding_lines(all_findings)
    lines.extend(finding_lines or ["  None"])
    lines.extend(["", "Workspace", f"  {workspace.domain}/", ""])
    return "\n".join(lines)


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "auto-config" and "--restore" in argv[1:]:
        from .core.autoconfig import restore_hosts
        result = restore_hosts()
        print(f"Auto-config restore: {result['status']}")
        return 0
    if argv and argv[0] == "doctor":
        from .doctor import report
        return report()
    if argv and argv[0] == "scan":
        argv = argv[1:]
    p = argparse.ArgumentParser(description="Enumerate AD CS and explain ESC1 candidates")
    p.add_argument("--dc", "--dc-ip", "-dc-ip", dest="dc"); p.add_argument("--port", type=int, default=None); p.add_argument("-domain", "--domain", required=True)
    p.add_argument("-u", "--username", required=True); p.add_argument("-p", "--password", help="omit to prompt")
    p.add_argument("--ldaps", action="store_true"); p.add_argument("--force-kerb", action="store_true")
    p.add_argument("--auto-config", action="store_true"); p.add_argument("--sync-time", action="store_true")
    p.add_argument("--verbose", "--debug", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--tool-output", action="store_true",
                   help="stream external collector output live (verbose; final report still rendered)")
    p.add_argument("--html-out", metavar="FILE", help="optionally write a standalone HTML report")
    p.add_argument("--timeout", type=float, default=10)
    p.add_argument("--modules", default="all", help="comma-separated modules (default: all read-only collectors)")
    p.add_argument("--profile", default="default")
    p.add_argument("--certipy-json", help="optional Certipy -json result for corroboration")
    p.add_argument("--cred1-dp", metavar="HOST_OR_IP",
                   help="optionally run one bounded safe CRED-1 PXE query against a known DP")
    # The output directory is the parent of the canonical domain workspace.
    # Keeping the default as the current directory makes new scans land in
    # ./<canonical-domain>/ while preserving the explicit --output-dir API.
    p.add_argument("--output-dir", default=".")
    a = p.parse_args(argv)
    console = Console(no_color=a.no_color, verbose=a.verbose, debug=a.verbose)
    console.banner(files("ad_enum").joinpath("assets/banner.txt").read_text(encoding="utf-8"))
    if a.password is None:
        import getpass; a.password = getpass.getpass("LDAP password: ")
    target = a.dc or a.domain
    try:
        ipaddress.ip_address(a.domain)
        bind_domain = ""
    except ValueError:
        bind_domain = a.domain
    console.line(); console.line("Checking credentials...")
    auto_state = None
    if a.auto_config or a.sync_time:
        auto_state = inspect_autoconfig(a.dc or target, a.domain)
        if a.sync_time:
            before = auto_state.get("skew_human", auto_state.get("skew_seconds", "unknown"))
            console.line(f"Time: current clock difference {before}")
            sync_state = sync_clock(a.dc or target)
            if sync_state.get("status") != "SYNCED":
                console.status("Time synchronization failed", "FAILED")
                console.line("  Use --verbose for synchronization diagnostics.")
                if a.verbose: console.debug_line(str(sync_state))
                return 2
            auto_state = inspect_autoconfig(a.dc or target, a.domain)
            console.line(f"Time: synchronized; clock difference {auto_state.get('skew_human', 'unknown')}")
        elif a.force_kerb and auto_state.get("skew_seconds", 0) and abs(auto_state["skew_seconds"]) > 300:
            console.status(f"Kerberos clock skew detected: {auto_state.get('skew_human', 'too large')}", "WARNING")
            console.line("  Re-run with --sync-time.")
    collector = Collector(target, a.username, a.password, bind_domain, a.ldaps, a.port,
                          timeout=a.timeout, force_kerb=a.force_kerb)
    try:
        console.activity("Resolving target...")
        root, _ = collector.preflight()
        resolved_name = target
        try:
            if ipaddress.ip_address(target):
                reverse_name = socket.getfqdn(target)
                if reverse_name and reverse_name != target:
                    resolved_name = f"{reverse_name} ({target})"
        except ValueError:
            pass
        console.complete(f"Target resolved: {resolved_name}")
    except Exception as exc:
        failure = translate_kerberos_error(exc) if a.force_kerb else None
        if failure and failure.category != "bad-credentials":
            console.status(failure.message, "FAILED")
            if failure.hint: console.line(f"  {failure.hint}")
            if a.verbose: console.debug_line(f"Raw Kerberos error: {failure.raw}")
        else:
            message = str(exc).lower()
            if any(token in message for token in ("invalid credentials", "invalidcredential",
                                                  "logon failure", "bad password")):
                console.status("Credentials Invalid", "INVALID")
            elif isinstance(exc, (TimeoutError, socket.timeout)) or "timed out" in message or "timeout" in message:
                console.status("Credential validation failed — LDAP timeout", "FAILED")
            elif any(token in message for token in ("signing", "channel binding", "stronger authentication",
                                                    "confidentiality required")):
                console.status("Credential validation blocked by LDAP policy", "FAILED")
            else:
                console.status("Credential validity could not be established", "FAILED")
            if a.verbose: console.debug_line(f"preflight failed: {type(exc).__name__}: {exc}")
        return 2
    if not ipaddress.ip_address(a.domain) if False else False:
        pass
    try:
        ipaddress.ip_address(a.domain)
        supplied_is_ip = True
    except ValueError:
        supplied_is_ip = False
    if not supplied_is_ip and canonical_domain(a.domain) != canonical_domain(root):
        console.status(f"Domain mismatch: supplied {a.domain}, discovered {root}", "FAILED")
        return 2
    console.status("Credentials are Valid", "VALID")
    workspace = ScanWorkspace(a.output_dir, root, original_target=target)
    # Establish one scan-scoped accumulator before any analysis records
    # coverage; the final write changes scan status to COMPLETE.
    coverage = CoverageReport()
    sccm_result = {"hosts": [], "management_points": [], "distribution_points": [],
                   "site_servers": [], "sms_providers": [], "sql_servers": [],
                   "sup_wsus": [], "pxe": {"status": "NOT TESTED"}, "status": "NOT TESTED"}
    # All scan-scoped aggregates exist before any module can consume them.
    policy_findings, description_findings, ldap_secret_findings = [], [], []
    discovered_credentials = []
    workspace.write_json(workspace.root / "scan.json", {
        "status": "INCOMPLETE", "domain": root, "canonical_domain": workspace.domain,
        "target": target, "scan_id": workspace.scan_id,
    })
    console.activity("Checking anonymous LDAP posture...")
    anonymous_ldap = probe_anonymous_ldap(target, root, timeout=min(a.timeout, 5))
    console.complete("Anonymous LDAP posture complete", "WARNING" if anonymous_ldap.get("error") else "PASS")
    requested = []
    for module in (x.strip().lower() for x in a.modules.split(",") if x.strip()):
        if module == "all": requested.extend(("bloodhound", "adcs-certipy", "ldapdomaindump", "netexec", "ldap", "adcs-native", "kerberos", "delegation", "sccm-discovery", "relay", "networkhound", "gpo"))
        elif module == "adcs": requested.extend(("ldap", "adcs-native", "adcs-certipy"))
        else: requested.append(module)
    plan = ExecutionPlanner().plan(requested or ["adcs-native"])
    if a.verbose:
        console.heading("Execution plan")
        for item in plan: console.line(f"  {item.spec.name} ........ {item.status.value}{(' - ' + item.reason) if item.reason else ''}")
    imported_certipy = CertipyAdapter().from_json(a.certipy_json) if a.certipy_json else None
    context = ScanContext(workspace.domain, target, AuthContext(a.username, a.password, bind_domain),
                          workspace, timeout=a.timeout, scan_id=workspace.scan_id,
                          ldaps=a.ldaps, force_kerb=a.force_kerb,
                          tool_output=a.tool_output,
                          auto_config={"requested": a.auto_config},
                          kerberos_session=collector.kerberos_session)
    if a.auto_config or a.sync_time:
        context.auto_config = auto_state or inspect_autoconfig(a.dc or target, workspace.domain)
        context.dc_hostname = context.auto_config.get("dc_hostname", "")
        if a.verbose: console.debug_line(f"auto-config: {context.auto_config}")
    # Native LDAP is the discovery prerequisite for the multi-host plan.
    console.activity("Running Native LDAP...")
    root, cas, templates = collector.collect()
    console.complete("Native LDAP complete")
    context.kerberos_session = collector.kerberos_session
    inventory = native_inventory(collector.raw)
    native_counts = inventory.counts()
    context.targets = build_targets(inventory)
    privileged_sids = privileged_account_sids(inventory)
    def report_progress(stage, label, state=None, line=None):
        if stage == "start": console.activity(f"Running {label}...")
        elif stage == "tool": console.line(console.paint(f"[{label}{':stderr' if state == 'stderr' else ''}] {line.rstrip()}" , "dim" if state == "stderr" else None))
        elif state == "PASS": console.complete(f"{label} complete")
        elif state in {"FAILED", "PARTIAL"}: console.complete(f"{label} failed — continuing", "WARNING")
        else: console.complete(f"{label} unavailable — skipped", "SKIPPED")
    external_results, external_diagnostics = execute_external(
        context, plan, certipy_snapshot=imported_certipy, progress=report_progress)
    certipy_result = external_results.get("adcs-certipy", {}).get("snapshot") if external_results.get("adcs-certipy", {}).get("status") == "PASS" else None
    certipy = certipy_result or imported_certipy
    source_counts = {"native-ldap": native_counts}
    for result in external_results.values():
        obj = result.get("result", {}) if isinstance(result, dict) else {}
        if hasattr(obj.get("inventory") if isinstance(obj, dict) else None, "records"):
            inventory.merge(obj["inventory"])
    networkhound_result = external_results.get("networkhound", {}).get("result", {})
    console.activity("Enumerating AD DNS...")
    dns_map = build_dns_map(inventory, networkhound_result.get("inventory") if isinstance(networkhound_result, dict) else None)
    dns_zones = normalize_zones(collector.raw.get("dns_zones", []))
    dns_records = normalize_records(collector.raw.get("dns_records", []))
    dns_map = merge_into_dns_map(dns_map, dns_records)
    workspace.write_json(workspace.root / "dns-map.json", dns_map)
    workspace.write_json(workspace.findings_path("DNS", "zones.json"), dns_zones)
    workspace.write_json(workspace.findings_path("DNS", "records.json"), dns_records)
    workspace.write_json(workspace.findings_path("DNS", "findings.json"), [])
    workspace.write_text(workspace.module_dir("DNS") / "findings.txt", "")
    console.complete("AD DNS enumeration complete")
    workspace.write_json(workspace.findings_path("LDAP", "networking.json"),
                         {"sites": collector.raw.get("sites", []), "subnets": collector.raw.get("subnets", [])})
    workspace.write_json(workspace.findings_path("NetworkHound", "inventory.json"),
                         networkhound_result.get("inventory", {}) if isinstance(networkhound_result, dict) else {})
    workspace.write_json(workspace.findings_path("NetworkHound", "dns-map.json"), dns_map)
    pso_inventory = normalize_password_settings(collector.raw.get("password_settings", []))
    resultants = []
    for record in inventory.records.get("users", {}).values():
        resultant = record.attributes.get("msDS-ResultantPSO")
        if resultant:
            resultants.append({"account": record.identifier, "resultant_pso": resultant[0] if isinstance(resultant, list) else resultant,
                               "privileged": record.identifier in privileged_sids})
    workspace.write_json(workspace.findings_path("PasswordPolicies", "inventory.json"),
                         {"policies": pso_inventory, "resultant_policies": resultants})
    workspace.write_json(workspace.findings_path("PasswordPolicies", "findings.json"), [])
    workspace.write_text(workspace.module_dir("PasswordPolicies") / "findings.txt", "")
    coverage.add("AD DNS / integrated records", "PASS", f"{len(dns_zones)} zone(s), {len(dns_records)} record(s)")
    coverage.add("Password policies / FGPP", "PASS", f"{len(collector.raw.get('password_settings', []))} PSO(s)")
    console.activity("Checking LDAP security...")
    smb_inventory, smb_findings = [], []
    console.activity("Checking anonymous SMB posture...")
    anonymous_smb = []
    seen_anon_hosts = set()
    for host_record in inventory.records.get("observed_hosts", {}).values():
        attrs = host_record.attributes
        host = attrs.get("host") or attrs.get("hostname") or attrs.get("name") or host_record.identifier
        ip = attrs.get("ip") or ""
        if host and str(host).lower() not in seen_anon_hosts:
            seen_anon_hosts.add(str(host).lower())
            anonymous_smb.append(probe_anonymous_smb(host, ip, timeout=min(a.timeout, 5)))
    if target not in seen_anon_hosts:
        anonymous_smb.append(probe_anonymous_smb(target, a.dc, timeout=min(a.timeout, 5)))
    anonymous_smb_findings = []
    for posture in anonymous_smb:
        if posture.get("share_enumeration") == "SHARE_ENUM_ALLOWED" and posture.get("shares"):
            anonymous_smb_findings.append(NormalizedFinding(
                finding_id=f"smb:anonymous-shares:{posture.get('host')}", category="SMB",
                rule="anonymous-share-enumeration",
                title=f"Anonymous share enumeration allowed — {posture.get('host')}",
                affected_object=posture.get("host"), domain=workspace.domain,
                sources=[{"source": source, "observed": True} for source in posture.get("sources", [])],
                evidence={"shares": posture.get("shares", []), "impact": "Unauthenticated users can enumerate SMB shares"},
                status="single-source", priority="medium", workspace_artifacts=["SMB/anonymous.json"],
                first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    workspace.write_json(workspace.findings_path("SMB", "anonymous.json"), anonymous_smb)
    console.complete("Anonymous SMB posture complete",
                    "WARNING" if any(x.get("error") for x in anonymous_smb) else "PASS")
    trust_inventory = normalize_trusts(collector.raw.get("trusts", []))
    workspace.write_json(workspace.findings_path("Trusts", "inventory.json"), trust_inventory)
    workspace.write_json(workspace.findings_path("Trusts", "findings.json"), [])
    workspace.write_text(workspace.module_dir("Trusts") / "findings.txt", "")
    ldap_security = {"signing": {"state": "UNKNOWN", "evidence": [],
                                  "reason": "no direct unsigned-bind policy/protocol observation"},
                     "channel_binding": {"state": "UNKNOWN", "evidence": [],
                                          "reason": "LDAPS channel binding cannot be assessed without a valid TLS service"}}
    ldap_security_findings = []
    if anonymous_ldap.get("domain_data") == "READABLE":
        ldap_security_findings.append(NormalizedFinding(
            finding_id="ldap:anonymous-directory-enumeration", category="LDAP",
            rule="anonymous-directory-enumeration",
            title=f"Anonymous directory enumeration allowed — {context.dc_hostname or target}",
            affected_object=context.dc_hostname or target, domain=workspace.domain,
            sources=[{"source": source, "observed": True} for source in anonymous_ldap.get("sources", [])],
            evidence={"posture": anonymous_ldap, "impact": "Unauthenticated users can enumerate Active Directory information"},
            status="single-source", priority="high", workspace_artifacts=["LDAPSecurity/anonymous.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    workspace.write_json(workspace.findings_path("LDAPSecurity", "anonymous.json"), anonymous_ldap)
    # A successful authenticated NTLM bind over plain LDAP is a direct,
    # read-only observation that the DC accepts an unsigned bind.  Do not
    # infer this from RelayKing, and do not claim a result for Kerberos SASL
    # or LDAPS transports that provide different protection semantics.
    if not a.ldaps and not a.force_kerb:
        ldap_security["signing"] = {"state": "NOT REQUIRED",
                                     "evidence": ["authenticated NTLM bind over LDAP/389 succeeded"],
                                     "reason": "plain LDAP bind accepted"}
        ldap_security_findings.append(NormalizedFinding(
            finding_id="ldap:signing-not-required", category="LDAP", rule="ldap-signing-not-required",
            title=f"LDAP signing not required — {context.dc_hostname or target}", affected_object=context.dc_hostname or target,
            domain=workspace.domain, sources=[{"source": "native-ldap", "observed": True}],
            evidence={"state": "NOT REQUIRED", "impact": "NTLM authentication may be relayable to LDAP when other prerequisites are satisfied"},
            status="single-source", priority="medium", workspace_artifacts=["LDAPSecurity/inventory.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    workspace.write_json(workspace.findings_path("LDAPSecurity", "inventory.json"), ldap_security)
    workspace.write_json(workspace.findings_path("LDAPSecurity", "findings.json"), ldap_security_findings)
    workspace.write_text(workspace.module_dir("LDAPSecurity") / "findings.txt",
                         "\n".join(f"[{x['category']}] {x['title']}" for x in ldap_security_findings) +
                         ("\n" if ldap_security_findings else ""))
    console.complete("LDAP security analysis complete")
    findings, comparisons, coverage, dangling, duplicates = scan(cas, templates, certipy=certipy, coverage=coverage)
    coverage.add("LDAP / anonymous posture", "PARTIAL" if anonymous_ldap.get("error") else "PASS",
                 f"bind={anonymous_ldap.get('bind')}, domain-data={anonymous_ldap.get('domain_data')}")
    coverage.add("SMB / anonymous posture", "PARTIAL" if any(x.get("error") for x in anonymous_smb) else "PASS",
                 f"{len(anonymous_smb)} host(s) bounded")
    exposures = roastable(inventory)
    delegation_records = enumerate_delegation(inventory)
    gmsa_records = enumerate_gmsa(inventory)
    workspace.write_json(workspace.findings_path("Kerberos", "inventory.json"),
                         {key: [item.as_dict() for item in value] for key, value in exposures.items()})
    workspace.write_json(workspace.findings_path("Delegation", "inventory.json"),
                         {"delegation": [item.as_dict() for item in delegation_records],
                          "gmsa": gmsa_records})
    workspace.write_json(workspace.findings_path("Kerberos", "gmsa.json"), gmsa_records)
    coverage.add("Kerberos / account exposure", "PASS", "native LDAP account flags and SPNs")
    coverage.add("Delegation / LDAP configuration", "PASS", "UAC, constrained delegation, and RBCD observations")
    domain_security = {"machine_account_quota": collector.raw.get("machineAccountQuota", "unknown"),
                       "account_flag_observations": [], "privileged_sids": sorted(privileged_sids)}
    domain_security_findings = []
    for record in inventory.records.get("users", {}).values():
        item = account_exposure(record)
        high_value = item.identifier in privileged_sids or bool(item.spns) or item.flags.get("DONT_REQ_PREAUTH") or item.flags.get("PASSWD_NOTREQD")
        account_context = account_security_context(item, privileged=item.identifier in privileged_sids)
        if item.enabled and (item.flags.get("ENCRYPTED_TEXT_PWD_ALLOWED") or item.flags.get("USE_DES_KEY_ONLY") or
                             (item.flags.get("DONT_EXPIRE_PASSWORD") and high_value)):
            domain_security["account_flag_observations"].append({"account": item.username, "sid": item.identifier,
                "encrypted_text_password_allowed": item.flags.get("ENCRYPTED_TEXT_PWD_ALLOWED", False),
                "des_only": item.flags.get("USE_DES_KEY_ONLY", False),
                "password_never_expires": item.flags.get("DONT_EXPIRE_PASSWORD", False),
                "privileged": item.identifier in privileged_sids, "service_account": bool(item.spns), "sources": item.sources})
        if not item.enabled:
            continue
        if item.flags.get("ENCRYPTED_TEXT_PWD_ALLOWED"):
            domain_security_findings.append(NormalizedFinding(
                finding_id=f"account:reversible-encryption:{item.identifier}", category="ACCOUNT",
                rule="reversible-password-encryption", title=f"Reversible password encryption allowed — {item.username}",
                affected_object=item.username, domain=workspace.domain,
                sources=[{"source": source, "observed": True} for source in item.sources],
                evidence={"userAccountControl": item.attributes.get("userAccountControl"), "privileged": item.identifier in privileged_sids},
                status="corroborated" if len(item.sources) > 1 else "single-source", priority="high",
                workspace_artifacts=["DomainSecurity/inventory.json"], first_seen_scan=workspace.scan_id,
                current_scan=workspace.scan_id).as_dict())
        if item.flags.get("USE_DES_KEY_ONLY"):
            domain_security_findings.append(NormalizedFinding(
                finding_id=f"kerberos:des-only:{item.identifier}", category="KERBEROS",
                rule="des-only-kerberos", title=f"DES-only Kerberos enabled — {item.username}",
                affected_object=item.username, domain=workspace.domain,
                sources=[{"source": source, "observed": True} for source in item.sources],
                evidence={"userAccountControl": item.attributes.get("userAccountControl"), "privileged": item.identifier in privileged_sids},
                status="corroborated" if len(item.sources) > 1 else "single-source", priority="high",
                workspace_artifacts=["DomainSecurity/inventory.json"], first_seen_scan=workspace.scan_id,
                current_scan=workspace.scan_id).as_dict())
        if item.flags.get("DONT_EXPIRE_PASSWORD") and high_value:
            domain_security_findings.append(NormalizedFinding(
                finding_id=f"account:password-never-expires:{item.identifier}", category="ACCOUNT",
                rule="password-never-expires", title=f"Password never expires — {item.username}",
                affected_object=item.username, domain=workspace.domain,
                sources=[{"source": source, "observed": True} for source in item.sources],
                evidence={"userAccountControl": item.attributes.get("userAccountControl"),
                          "privileged": item.identifier in privileged_sids, "service_account": bool(item.spns)},
                status="corroborated" if len(item.sources) > 1 else "single-source", priority="medium",
                workspace_artifacts=["DomainSecurity/inventory.json"], first_seen_scan=workspace.scan_id,
                current_scan=workspace.scan_id).as_dict())
        if item.identifier in privileged_sids and account_context["last_logon_age_days"] is not None and account_context["last_logon_age_days"] >= 180:
            domain_security_findings.append(NormalizedFinding(
                finding_id=f"account:stale-privileged:{item.identifier}", category="ACCOUNT",
                rule="stale-privileged-account", title=f"Stale privileged account — {item.username}",
                affected_object=item.username, domain=workspace.domain,
                sources=[{"source": source, "observed": True} for source in item.sources],
                evidence={"enabled": True, "lastLogonTimestamp": account_context["lastLogonTimestamp"],
                          "last_logon_age_days": account_context["last_logon_age_days"],
                          "timestamp_semantics": "replicated approximate value", "privileged": item.identifier in privileged_sids},
                status="corroborated" if len(item.sources) > 1 else "single-source", priority="medium",
                workspace_artifacts=["DomainSecurity/inventory.json"], first_seen_scan=workspace.scan_id,
                current_scan=workspace.scan_id).as_dict())
    domain_security["privileged_sids"] = sorted(privileged_sids)
    workspace.write_json(workspace.findings_path("DomainSecurity", "inventory.json"), domain_security)
    workspace.write_json(workspace.findings_path("DomainSecurity", "findings.json"), domain_security_findings)
    workspace.write_text(workspace.module_dir("DomainSecurity") / "findings.txt",
                         "\n".join(f"[{x['category']}] {x['title']}" for x in domain_security_findings) +
                         ("\n" if domain_security_findings else ""))
    labels = {"bloodhound": "BloodHound", "adcs-certipy": "Certipy",
              "ldapdomaindump": "LDAPDomainDump", "netexec": "NetExec"}
    for module_id, result in external_results.items():
        status = result.get("status")
        coverage_status = {"PASS": "PASS", "FAILED": "FAILED", "UNAVAILABLE": "NOT AVAILABLE"}.get(status, "NOT CHECKED")
        coverage.add(f"External / {labels.get(module_id, module_id)}", coverage_status,
                     result.get("reason", "collector completed"))
        if a.verbose:
            result_obj = result.get("result", {})
            inv = result_obj.get("inventory") if isinstance(result_obj, dict) else None
            if hasattr(inv, "counts"):
                counts = inv.counts()
                source_counts[result_obj.get("source", module_id)] = counts
                console.line(f"  {labels.get(module_id, module_id)}: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
            elif status == "PASS":
                console.line(f"  {labels.get(module_id, module_id)}: collected")
    ldd_result = external_results.get("ldapdomaindump", {}).get("result", {})
    ldd_inv = ldd_result.get("inventory") if isinstance(ldd_result, dict) else None
    if hasattr(ldd_inv, "records"):
        native_users = inventory.records.get("users", {})
        ldd_users = ldd_inv.records.get("users", {})
        descriptions = sum(bool(r.attributes.get("description")) for r in ldd_users.values())
        if a.verbose: console.line(f"  LDAPDomainDump users with descriptions: {descriptions}")
    for module_id, result in external_results.items():
        result_obj = result.get("result", {}) if isinstance(result, dict) else {}
        if result_obj.get("password_policy"):
            inventory.password_policy = result_obj["password_policy"]
        if result_obj.get("hosts"):
            for host in result_obj["hosts"]:
                inventory.add("observed_hosts", f"{host.get('ip')}:{host.get('host', host.get('name', ''))}", host, "netexec")
    # NetExec host observations are added above; normalize SMB only after
    # that merge so the module cannot emit an empty inventory.
    smb_inventory = normalize_smb(inventory)
    console.activity("Enumerating SMB shares...")
    share_inventory = []
    for result in external_results.values():
        result_obj = result.get("result", {}) if isinstance(result, dict) else {}
        for share in result_obj.get("shares", []) if isinstance(result_obj, dict) else []:
            key = (str(share.get("ip")), str(share.get("share", "")).lower())
            if not any((str(x.get("ip")), str(x.get("share", "")).lower()) == key for x in share_inventory):
                share_inventory.append({**share, "sources": [share.get("source", "netexec")]})
    workspace.write_json(workspace.findings_path("SMB", "inventory.json"), smb_inventory)
    workspace.write_json(workspace.findings_path("SMB", "shares.json"), share_inventory)
    unsigned = [x for x in smb_inventory if x.get("smb_signing") is False]
    if unsigned:
        smb_findings.append(NormalizedFinding(
            finding_id="smb:signing-not-required", category="SMB", rule="signing-not-required",
            title=f"SMB signing not required — {len(unsigned)} host(s)", affected_object=workspace.domain,
            domain=workspace.domain, sources=[{"source": source, "observed": True} for source in sorted({s for x in unsigned for s in x["sources"]})],
            evidence={"hosts": unsigned}, status="single-source", priority="medium",
            workspace_artifacts=["SMB/inventory.json"], first_seen_scan=workspace.scan_id,
            current_scan=workspace.scan_id).as_dict())
    for share in share_inventory:
        if share.get("writable") and not is_standard_admin_share(share.get("share")):
            smb_findings.append(NormalizedFinding(
                finding_id=f"smb:writable-share:{share.get('ip')}:{share.get('share')}", category="SMB",
                rule="writable-share", title=f"Writable SMB share — {share.get('host') or share.get('ip')}\\{share.get('share')}",
                affected_object=share.get("unc", share.get("share", "unknown")), domain=workspace.domain,
                sources=[{"source": source, "observed": True} for source in share.get("sources", [])],
                evidence={"share": share, "impact": "Low-privileged users can modify share content"},
                status="single-source", priority="medium", workspace_artifacts=["SMB/shares.json"],
                first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    smb_findings.extend(anonymous_smb_findings)
    workspace.write_json(workspace.findings_path("SMB", "findings.json"), smb_findings)
    workspace.write_text(workspace.module_dir("SMB") / "findings.txt", "\n".join(f"[{x['category']}] {x['title']}" for x in smb_findings) + ("\n" if smb_findings else ""))
    coverage.add("SMB / share inventory", "PASS" if share_inventory else "PARTIAL", f"{len(share_inventory)} share(s)")
    coverage.add("SMB / anonymous posture", "PARTIAL" if any(x.get("error") for x in anonymous_smb) else "PASS",
                 f"{len(anonymous_smb)} host(s) bounded")
    console.complete("SMB share enumeration complete", "PASS" if share_inventory else "WARNING")
    console.activity("Enumerating SCCM...")
    sccm_result = discover_sccm(inventory, collector.raw, dns_map)
    sccm_result["endpoint_probes"] = probe_management_points(sccm_result.get("management_points", []), a.timeout)
    for mp in sccm_result.get("management_points", []):
        probes = [x for x in sccm_result["endpoint_probes"] if x["host"].lower() == mp["host"].lower()]
        confirmed = [x for x in probes if x.get("sccm_marker")]
        if confirmed:
            mp["protocol"] = confirmed[0]["scheme"]
            mp["port"] = confirmed[0]["port"]
            mp["endpoint_evidence"] = [{"scheme": x["scheme"], "path": x["path"],
                                         "http_status": x.get("http_status"), "metadata": x.get("metadata", {})}
                                        for x in confirmed]
    workspace.write_json(workspace.findings_path("SCCM", "inventory.json"), sccm_result)
    workspace.write_json(workspace.findings_path("SCCM", "topology.json"),
                         sccm_result.get("topology", {}))
    workspace.write_json(workspace.raw_dir("SCCM") / "ldap-publication.json", collector.raw.get("sccm", []))
    workspace.write_json(workspace.findings_path("SCCM", "endpoints.json"), sccm_result.get("endpoint_probes", []))
    workspace.write_json(workspace.findings_path("SCCM", "pxe.json"), sccm_result.get("pxe", {}))
    workspace.write_json(workspace.findings_path("SCCM", "dp-content.json"),
                         sccm_result.get("dp_content", []))
    workspace.write_json(workspace.findings_path("SCCM", "task-sequences.json"),
                         sccm_result.get("task_sequences", []))
    cred1_targets = [a.cred1_dp] if a.cred1_dp else cred1_candidates(sccm_result)
    if cred1_targets:
        console.activity("Checking SCCM CRED-1 PXE exposure...")
        cred1_results = []
        cinder_executable = cinderpath_path()
        setup_decision = None
        for cred1_target in cred1_targets[:4]:
            runtime = check_cred1_runtime(cred1_target, cinder_executable)
            if runtime.get("capability_fixable") and setup_decision is None:
                if sys.stdin.isatty() and sys.stdout.isatty():
                    console.line("SCCM/PXE credential checks require packet-capture capabilities.")
                    console.line(f"  CinderPath .......... {'INSTALLED' if cinder_executable else 'MISSING'}")
                    console.line(f"  Interface ........... {runtime.get('interface') or 'UNKNOWN'}")
                    answer = input("Configure CinderPath packet-capture capability now? [y/N] ")
                    setup_decision = answer.strip().lower() in {"y", "yes"}
                    if setup_decision:
                        ok, reason = fix_cinderpath_capabilities(cinder_executable)
                        if not ok:
                            setup_decision = False
                            runtime["setup_error"] = reason
                        else:
                            runtime = check_cred1_runtime(cred1_target, cinder_executable)
                            runtime["setup"] = reason
                else:
                    setup_decision = False
            if setup_decision is False and runtime.get("capability_fixable"):
                runtime["reasons"].append("setup declined or noninteractive execution")
            if runtime["status"] != "READY":
                cred1_results.append({"dp": cred1_target, "pxe": "NOT TESTED", "wds": "NOT TESTED",
                                      "tftp": "NOT TESTED", "media_protection": "UNKNOWN",
                                      "secret_inspection": "NOT ATTEMPTED", "evidence": runtime["reasons"],
                                      "sources": ["CRED-1 execution-host prerequisite check"],
                                      "runtime": runtime})
            else:
                cred1_results.append(run_cinderpath_cred1(cred1_target, timeout=min(a.timeout, 60),
                                                         executable=cinder_executable))
        sccm_result["cred1"] = cred1_results[0] if len(cred1_results) == 1 else cred1_results
        workspace.write_json(workspace.findings_path("SCCM", "cred1.json"), sccm_result["cred1"])
        cred1_status = "PASS" if any(x.get("pxe") == "CONFIRMED" for x in cred1_results) else "PARTIAL"
        coverage.add("SCCM / CRED-1 safe PXE acquisition", cred1_status,
                     f"{len(cred1_results)} discovered DP candidate(s) checked")
        full_cred1 = any(str(x.get("status", "")).upper() in {"CONFIRMED", "COMPLETE"}
                         and str(x.get("secret_inspection", "")).upper() == "COMPLETE"
                         for x in cred1_results)
        coverage.add("SCCM / CRED-1 deterministic recovery",
                     "PASS" if any(x.get("credentials") for x in cred1_results) or full_cred1 else "PARTIAL",
                     "CinderPath adapter completed bounded read/decode path")
        console.complete("SCCM CRED-1 PXE analysis complete")
    else:
        coverage.add("SCCM / CRED-1 safe PXE acquisition", "NOT TESTED",
                     "use --cred1-dp with one known distribution point")
    coverage.add("SCCM / infrastructure discovery", "PASS", f"{len(sccm_result.get('hosts', []))} candidate host(s)")
    # Keep SCCM coverage granular: the aggregate line describes the
    # discovery family only and must not imply that every role is observable.
    coverage.add("SCCM / topology", "PASS", "normalized site and role candidates")
    coverage.add("SCCM / management point", "PASS" if sccm_result.get("management_points") else "PARTIAL",
                 f"{len(sccm_result.get('management_points', []))} candidate(s)")
    for capability in ("distribution point", "PXE / WDS", "boot metadata", "task-sequence metadata",
                       "SQL association", "SUP / WSUS", "SCCM ACL", "DP content metadata"):
        coverage.add(f"SCCM / {capability}", "NOT TESTED", "requires live role evidence")
    if cred1_targets:
        cred1_complete = any(str(x.get("status", "")).upper() in {"CONFIRMED", "COMPLETE"}
                             and str(x.get("secret_inspection", "")).upper() == "COMPLETE"
                             for x in cred1_results)
        if cred1_complete:
            for capability in ("distribution point", "PXE / WDS", "boot metadata", "task-sequence metadata"):
                coverage.add(f"SCCM / {capability}", "PASS", "validated by CinderPath CRED-1 adapter")
    console.complete("SCCM analysis complete")
    console.activity("Enumerating MSSQL infrastructure...")
    mssql_inventory = normalize_mssql(inventory)
    workspace.write_json(workspace.findings_path("MSSQL", "inventory.json"), mssql_inventory)
    workspace.write_json(workspace.findings_path("MSSQL", "instances.json"), mssql_inventory)
    workspace.write_json(workspace.findings_path("MSSQL", "relationships.json"),
                         [x for x in mssql_inventory if x.get("sccm")])
    workspace.write_json(workspace.findings_path("MSSQL", "findings.json"), [])
    workspace.write_text(workspace.module_dir("MSSQL") / "findings.txt", "")
    coverage.add("MSSQL / SPN instance inventory", "PASS",
                 f"{len(mssql_inventory)} instance candidate(s)")
    console.complete("MSSQL analysis complete")
    console.activity("Enumerating DFS infrastructure...")
    dfs_inventory = normalize_dfs(collector.raw.get("dfs", []))
    correlate_dfs_targets(dfs_inventory, share_inventory)
    workspace.write_json(workspace.findings_path("DFS", "namespaces.json"), dfs_inventory)
    workspace.write_json(workspace.findings_path("DFS", "targets.json"),
                         [{"namespace": x["namespace"], "path": x["path"], "target": target,
                           "source": x["source"]} for x in dfs_inventory for target in x["targets"]])
    workspace.write_json(workspace.findings_path("DFS", "findings.json"), [])
    workspace.write_text(workspace.module_dir("DFS") / "findings.txt", "")
    dfs_collection = collector.raw.get("dfs_collection", {})
    dfs_status = ("PASS" if dfs_collection.get("status") == "PASS" else "FAILED") if dfs_collection else "PARTIAL"
    dfs_detail = (f"{len(dfs_inventory)} namespace/link observation(s)"
                  if dfs_collection.get("status") == "PASS" else
                  (dfs_collection.get("error", "collection status unavailable") if dfs_collection else "LDAP DFS query not performed"))
    coverage.add("DFS / LDAP query", dfs_status, dfs_detail)
    coverage.add("DFS / namespace inventory", dfs_status,
                 f"{len(dfs_inventory)} namespace/link observation(s)")
    coverage.add("DFS / target parsing", dfs_status, f"{sum(len(x.get('targets', [])) for x in dfs_inventory)} target(s)")
    coverage.add("DFS / SMB correlation", dfs_status,
                 f"{sum(1 for x in dfs_inventory for y in x.get('target_access', []) if y.get('source') == 'SMB share inventory')} observed target(s)")
    console.complete("DFS analysis complete")
    console.activity("Checking remote management exposure...")
    service_inventory = normalize_services([x.attributes for x in inventory.records.get("observed_hosts", {}).values()])
    service_targets = list(context.targets)
    service_targets.extend({"host": x.get("host"), "ip": x.get("ip")} for x in smb_inventory)
    service_ports = dict(DEFAULT_SERVICES)
    service_ports.update({int(x["port"]): "MSSQL" for x in mssql_inventory if x.get("port")})
    # SPN publication is useful corroboration but is not required for a
    # known SQL host. Probe standard TDS for explicitly named SQL targets.
    if any("mssql" in str(x.get("host") or x.get("fqdn") or x.get("hostname") or "").lower()
           for x in service_targets if isinstance(x, dict)):
        service_ports[1433] = "MSSQL"
    service_probes = probe_known_services(service_targets, ports=service_ports,
                                          timeout=min(a.timeout, 2), max_hosts=64)
    service_inventory.extend(service_probes)
    service_inventory = sorted({(x.get("host"), x.get("service"), x.get("port")): x
                                for x in service_inventory}.values(),
                               key=lambda x: (str(x.get("host", "")).lower(), str(x.get("service", "")), x.get("port") or 0))
    tds_observations = [x for x in service_inventory if str(x.get("service", "")).upper() == "MSSQL"]
    coverage.add("MSSQL / TDS PRELOGIN", "PASS" if tds_observations else "NOT TESTED",
                 f"{sum(x.get('tds') == 'CONFIRMED' for x in tds_observations)} confirmed endpoint(s); "
                 f"{len(tds_observations)} candidate host(s) probed")
    workspace.write_json(workspace.findings_path("Services", "inventory.json"), service_inventory)
    workspace.write_json(workspace.findings_path("Services", "findings.json"), [])
    workspace.write_text(workspace.module_dir("Services") / "findings.txt", "")
    coverage.add("Services / bounded exposure inventory", "PASS" if service_inventory else "PARTIAL",
                 f"{len(service_inventory)} service observation(s)")
    console.complete("Service exposure analysis complete")
    access_records = from_netexec_hosts(
        external_results.get("netexec", {}).get("result", {}).get("hosts", []), a.username)
    access_records.append({"host": resolved_name, "ip": target, "protocol": "LDAP",
                           "port": a.port or (636 if a.ldaps else 389),
                           "principal": a.username, "authentication": "AUTHENTICATED",
                           "privilege": "UNKNOWN", "source": "Native LDAP",
                           "evidence": {"authenticated_collection": True}})
    nxc = NetExecAdapter()
    if nxc.resolve_executable():
        # Service observations bound the authentication checks to known,
        # relevant endpoints.  The adapter performs at most one attempt for
        # each identity/host/protocol tuple and never receives artifact creds.
        access_targets = filter_redundant_access_targets(service_inventory, access_records)
        access_records.extend(nxc.run_access_checks(context=context, targets=access_targets))
    access_records = merge_access(access_records)
    if any(item.get("authentication") == "AUTHENTICATED" and item.get("protocol") == "SMB"
           for item in access_records):
        coverage.add("Access / current-identity SMB auth", "PASS", "bounded NetExec authentication check")
    elif nxc.resolve_executable():
        coverage.add("Access / current-identity SMB auth", "PASS", "bounded NetExec check returned no success")
    else:
        coverage.add("Access / current-identity SMB auth", "NOT TESTED", "NetExec is not installed")
    coverage.add("Access / current-identity LDAP auth", "PASS", "native LDAP collection authenticated")
    for protocol in ("SSH", "RDP", "WINRM", "MSSQL"):
        observed = any(item.get("protocol") == protocol for item in access_records)
        coverage.add(f"Access / current-identity {protocol} auth",
                     "PASS" if observed else "NOT TESTED",
                     "bounded NetExec authentication check" if observed else "no observed candidate or NetExec unavailable")
    workspace.write_json(workspace.findings_path("Access", "inventory.json"), access_records)
    workspace.write_json(workspace.findings_path("Access", "findings.json"), [])
    workspace.write_text(workspace.module_dir("Access") / "findings.txt", "")
    console.activity("Analyzing trust relationships...")
    trust_context = normalize_trust_context(collector.raw.get("trusts", []))
    workspace.write_json(workspace.findings_path("Trusts", "inventory.json"), trust_context)
    workspace.write_json(workspace.findings_path("Trusts", "foreign-principals.json"),
                         collector.raw.get("foreign_security_principals", []))
    coverage.add("Trusts / relationship context", "PASS", f"{len(trust_context)} trust(s)")
    console.complete("Trust analysis complete")
    console.activity("Correlating privilege paths...")
    path_edges = collector.raw.get("privilege_edges", [])
    paths = build_privilege_paths(path_edges)
    workspace.write_json(workspace.findings_path("Paths", "inventory.json"), paths)
    workspace.write_json(workspace.findings_path("Paths", "findings.json"), [])
    workspace.write_text(workspace.module_dir("Paths") / "findings.txt", "")
    coverage.add("Paths / bounded privilege correlation", "PASS" if path_edges else "PARTIAL",
                 f"{len(paths)} bounded path(s)")
    console.complete("Privilege-path correlation complete")
    expected_acl_principals = {
        str(record.identifier) for record in inventory.records.get("users", {}).values()
        if str((record.attributes.get("sAMAccountName", [""])[0]
                if isinstance(record.attributes.get("sAMAccountName", [""]), list)
                else record.attributes.get("sAMAccountName", ""))).lower() == str(a.username).lower()
    }
    console.activity("Inspecting GPOs and SYSVOL...")
    gpos = attach_gpo_links(normalize_gpos(collector.raw.get("gpos", [])),
                            collector.raw.get("gpo_links", []))
    gpo_acls = normalize_gpo_acls(collector.raw.get("gpos", []))
    gpo_by_name = {str(x.get("display_name", "")).lower(): x for x in gpos}
    for acl in gpo_acls:
        scope = gpo_by_name.get(str(acl.get("gpo", "")).lower(), {}).get("scope", {})
        acl["scope"] = scope
    gpo_acl_observations = analyze_effective_acls(
        gpo_acls, inventory, expected_principal_sids=expected_acl_principals)
    for observation in gpo_acl_observations:
        observation["scope"] = gpo_by_name.get(str(observation["target"]).lower(), {}).get("scope", {})
    high_value_acls = normalize_security_descriptors(collector.raw.get("security_descriptors", []))
    high_value_acl_observations = analyze_effective_acls(
        high_value_acls, inventory, expected_principal_sids=expected_acl_principals)
    sysvol = collect_sysvol(context, gpos)
    netlogon = collect_netlogon(context)
    gpo_findings = []
    gpo_security_settings = []
    gpo_by_guid = {str(g.get("guid", "")).strip("{}").lower(): g for g in gpos}
    for item in sysvol.get("files", []):
        gpo = gpo_by_guid.get(str(item.get("gpo_guid", "")).strip("{}").lower(), {"guid": item.get("gpo_guid")})
        gpo_findings.extend(inspect_file(gpo, item["path"], item["content"]))
        for setting in parse_security_settings(item["path"], item["content"]):
            gpo_security_settings.append({**setting, "gpo": {"guid": gpo.get("guid"),
                                                               "display_name": gpo.get("display_name"),
                                                               "scope": gpo.get("scope", {})}})
        safe = dict(item); safe.pop("content", None)
        workspace.write_json(workspace.raw_dir("GPO") / (str(item["gpo_guid"]).strip("{}").lower() + ".json"), safe)
    workspace.write_json(workspace.findings_path("GPO", "inventory.json"), gpos)
    workspace.write_json(workspace.findings_path("GPO", "links.json"), collector.raw.get("gpo_links", []))
    workspace.write_json(workspace.findings_path("GPO", "acl.json"), gpo_acls)
    workspace.write_json(workspace.findings_path("GPO", "effective-rights.json"), gpo_acl_observations)
    workspace.write_json(workspace.findings_path("GPO", "policies.json"), {"status": sysvol.get("status"), "error": sysvol.get("error", ""), "files": [{k: v for k, v in x.items() if k != "content"} for x in sysvol.get("files", [])]})
    workspace.write_json(workspace.findings_path("GPO", "security-settings.json"), gpo_security_settings)
    workspace.write_json(workspace.findings_path("GPO", "findings.json"), gpo_findings)
    sysvol_dir = workspace.module_dir("GPO") / "SYSVOL"
    workspace.write_json(sysvol_dir / "inventory.json",
                         [{"gpo_guid": x.get("gpo_guid"), "path": x.get("path"), "name": x.get("name"),
                           "size": len(x.get("content", b"")), "inspection_status": "INSPECTED"}
                          for x in sysvol.get("files", [])])
    workspace.write_json(sysvol_dir / "findings.json", gpo_findings)
    workspace.write_text(workspace.module_dir("GPO") / "findings.txt",
                         "\n\n".join(
                             f"[GPO] {x['title']}\n  File: {x['file']}\n"
                             f"  Account: {x['account']}\n"
                             f"  {('cpassword' if x['rule'] == 'gpp-cpassword' else 'Password')}: "
                             f"{x['evidence'].get('value')}"
                             for x in gpo_findings) + ("\n" if gpo_findings else ""))
    workspace.write_json(workspace.module_dir("GPO") / "NETLOGON" / "inventory.json", netlogon)
    coverage.add("GPO / LDAP inventory", "PASS", f"{len(gpos)} group policy object(s)")
    gpo_status = {"PASS": "PASS", "FAILED": "FAILED", "UNAVAILABLE": "NOT AVAILABLE"}.get(sysvol.get("status"), "FAILED")
    coverage.add("GPO / SYSVOL targeted inspection", gpo_status, f"{len(sysvol.get('files', []))} file(s)")
    netlogon_status = {"PASS": "PASS", "FAILED": "FAILED", "UNAVAILABLE": "NOT AVAILABLE"}.get(netlogon.get("status"), "FAILED")
    coverage.add("GPO / NETLOGON targeted inventory", netlogon_status, f"{len(netlogon.get('files', []))} file(s)")
    coverage.add("GPO / security settings", "PASS" if gpo_status == "PASS" else "PARTIAL",
                 f"{len(gpo_security_settings)} setting observation(s)")
    console.complete("GPO analysis complete", "PASS" if gpo_status == "PASS" else "WARNING")
    laps_inventory = normalize_laps(collector.raw.get("laps_schema", []), inventory)
    workspace.write_json(workspace.findings_path("LAPS", "inventory.json"), laps_inventory)
    workspace.write_json(workspace.findings_path("LAPS", "findings.json"), [])
    workspace.write_text(workspace.module_dir("LAPS") / "findings.txt", "")
    privileged_names = {"domain admins", "enterprise admins", "administrators", "schema admins",
                        "account operators", "server operators", "backup operators", "dnsadmins",
                        "group policy creator owners"}
    privileged_groups = [{"name": r.attributes.get("sAMAccountName") or r.attributes.get("name") or r.identifier,
                          "sid": r.identifier, "sources": r.sources}
                         for r in inventory.records.get("groups", {}).values()
                         if str(r.attributes.get("sAMAccountName") or r.attributes.get("name") or "").lower() in privileged_names]
    workspace.write_json(workspace.findings_path("ACL", "privileged-groups.json"), privileged_groups)
    workspace.write_json(workspace.findings_path("ACL", "inventory.json"),
                         {"gpo_acls": gpo_acls, "high_value_acls": high_value_acls})
    acl_findings = []
    for observation in gpo_acl_observations + high_value_acl_observations:
        acl_target = observation["target"]
        rights = ", ".join(observation["effective_rights"])
        is_gpo = observation in gpo_acl_observations
        category, rule = ("GPO", "gpo-modify") if is_gpo else ("ACL", "high-value-right")
        if is_gpo:
            title = f"Low-privilege principal can modify GPO — {acl_target}"
        else:
            right_title = {
                "ModifyGroupMembership": "modify group membership",
                "ResetPassword": "reset password",
                "WriteServicePrincipalName": "write servicePrincipalName",
                "WriteDacl": "modify permissions",
                "WriteOwner": "take ownership",
            }
            labels = [right_title.get(x, x) for x in observation["effective_rights"]]
            title = f"Low-privilege principal can {', '.join(labels)} — {acl_target}"
        acl_findings.append(NormalizedFinding(
            finding_id=f"{category.lower()}:{rule}:{acl_target}:{observation['principal_sid']}",
            category=category, rule=rule, title=title, affected_object=acl_target,
            domain=workspace.domain,
            sources=[{"source": "native-ldap", "observed": True}],
            evidence={"principal_sid": observation["principal_sid"], "effective_rights": rights,
                      "principal_context": observation["principal_context"],
                      "scope": observation.get("scope", {}), "aces": observation["aces"]},
            status="single-source", priority="high",
            workspace_artifacts=["GPO/effective-rights.json" if is_gpo else "ACL/inventory.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    console.activity("Analyzing ACLs...")
    workspace.write_json(workspace.findings_path("ACL", "findings.json"), acl_findings)
    workspace.write_text(workspace.module_dir("ACL") / "findings.txt",
                         "\n".join(f"[{x['category']}] {x['title']}" for x in acl_findings) +
                         ("\n" if acl_findings else ""))
    console.complete("ACL analysis complete")
    coverage.add("SMB / signing posture", "PASS" if smb_inventory else "NOT CHECKED", f"{len(smb_inventory)} host(s)")
    coverage.add("LDAP / signing and channel binding", "NOT CHECKED", "posture unknown; no direct safe proof")
    coverage.add("Trusts / LDAP inventory", "PASS", f"{len(trust_inventory)} trust(s)")
    coverage.add("LAPS / schema and authorization inventory", "PASS", f"{len(laps_inventory.get('schema_attributes', []))} schema attribute(s)")
    relay_findings = []
    relay_result = external_results.get("relay", {})
    if relay_result.get("status") == "PASS":
        relay_data = relay_result.get("result", {}).get("json")
        relay_inventory = normalize_relayking(relay_data)
        workspace.write_json(workspace.findings_path("Relay", "inventory.json"),
                             {"source": "relayking", **relay_inventory, "safe_mode": True})
        relay_targets = []
        for host in inventory.records.get("observed_hosts", {}).values():
            if host.attributes.get("smb_signing") is False:
                relay_targets.append(f"{host.attributes.get('ip', host.identifier)}\tSMB signing not required")
        workspace.write_text(workspace.findings_path("Relay", "relay-targets.txt"),
                             "\n".join(relay_targets) + ("\n" if relay_targets else ""))
        coverage.add("Relay / safe exposure enumeration", "PASS", "RelayKing audit, no coercion")
        for path in relay_inventory["paths"]:
            if path.get("dest_protocol") in {"ldap", "http", "https", "mssql", "smb"}:
                relay_findings.append(NormalizedFinding(
                    finding_id=f"relay:path:{path.get('dest_host')}:{path.get('dest_protocol')}",
                    category="RELAY", rule="relay-path",
                    title=f"Potential NTLM relay path — {path.get('dest_host')} ({path.get('dest_protocol')})",
                    affected_object=path.get("dest_host", "unknown"), domain=workspace.domain,
                    sources=[{"source": "relayking", "vulnerable": True}], evidence=path,
                    status="single-source", priority="medium", workspace_artifacts=["Relay/inventory.json"],
                    first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    else:
        coverage.add("Relay / safe exposure enumeration", "NOT AVAILABLE" if relay_result.get("status") == "UNAVAILABLE" else "FAILED",
                     relay_result.get("reason", "RelayKing not executed"))
    workspace.write_json(workspace.root / "scan.json", {
        "status": "COMPLETE", "domain": root, "canonical_domain": workspace.domain, "target": target,
        "username": a.username, "scan_id": workspace.scan_id,
        "modules": [item.spec.id for item in plan],
        "execution_plan": [{"module": item.spec.id, "status": item.status.value, "reason": item.reason} for item in plan],
        "sources": ["ldap-native"] + ([key for key, value in external_results.items() if value.get("status") == "PASS"]),
        "artifacts": {"ldap_raw": "ADCS/raw/ldap.json", "findings": "ADCS/findings.json",
                      "coverage": "coverage.json", "summary": "summary.txt", "results": "results.txt"}
    })
    workspace.write_json(workspace.raw_dir("ADCS") / "ldap.json", collector.raw)
    if certipy:
        workspace.write_json(workspace.raw_dir("ADCS") / "certipy.json", certipy.raw_data)
    finding_records = []
    for template, ca, assessment in findings:
        if not assessment.vulnerable:
            continue
        comparison = comparisons[template.name]
        finding_records.append(NormalizedFinding(
            finding_id=f"adcs:esc1:{template.name}", category="ADCS", rule="ESC1",
            title=f"ESC1 — {template.name}", affected_object=template.dn or template.name,
            domain=workspace.domain,
            sources=[{"source": x.source, "vulnerable": x.vulnerable, "detail": x.detail,
                      "evidence": x.evidence} for x in comparison.assessments],
            evidence={"native": assessment.evidence},
            validation={"observations": [x.__dict__ for x in comparison.validations]},
            status=comparison.overall_status,
            workspace_artifacts=["ADCS/raw/ldap.json", "ADCS/findings.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    certipy_records = certipy.vulnerability_records() if certipy else []
    for item in certipy_records:
        if item["rule"].upper().startswith("ESC1") and any(
                x["affected_object"] == item["affected_object"] for x in finding_records):
            continue
        finding_records.append(NormalizedFinding(
            finding_id=f"adcs:certipy:{item['rule']}:{item['affected_object']}",
            category="ADCS", rule=item["rule"], title=f"{item['rule']} — {item['affected_object']}",
            affected_object=item["affected_object"], domain=workspace.domain,
            sources=[{"source": "certipy", "vulnerable": True,
                      "detail": item["explanation"], "evidence": item["evidence"]}],
            evidence={"certipy": item["evidence"]}, status="single-source",
            workspace_artifacts=["ADCS/raw/certipy.json"], first_seen_scan=workspace.scan_id,
            current_scan=workspace.scan_id).as_dict())
    workspace.write_json(workspace.findings_path("ADCS"), finding_records)
    workspace.write_text(workspace.module_dir("ADCS") / "findings.txt",
                          "\n".join(f"[{x['status']}] {x['title']}" for x in finding_records) + "\n")
    workspace.write_json(workspace.root / "coverage.json", coverage.as_dict())
    workspace.write_json(workspace.root / "inventory.json", inventory)
    workspace.write_json(workspace.root / "inventory-comparison.json", {
        "counts": {**source_counts,
                   "merged": inventory.counts(),
                   "ldapdomaindump": ldd_inv.counts() if hasattr(ldd_inv, "counts") else {}},
        "diagnostics": inventory.diagnostics,
        "password_policy": inventory.password_policy,
        "targets": context.targets,
    })
    # Small, descriptive inventory observations.  These are deliberately
    # separate from AD CS vulnerability rules.
    policy = inventory.password_policy.get("canonical", {})
    if policy.get("complexity_enabled") is False:
        policy_findings.append(NormalizedFinding(
            finding_id="policy:password-complexity-disabled", category="POLICY",
            rule="password-complexity", title="Password complexity disabled",
            affected_object=root, domain=workspace.domain,
            evidence={"canonical": policy, "raw": inventory.password_policy},
            status="corroborated" if "netexec" in str(inventory.password_policy) else "single-source",
            priority="medium", workspace_artifacts=["inventory-comparison.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    if isinstance(policy.get("minimum_password_length"), int) and policy["minimum_password_length"] < 8:
        policy_findings.append(NormalizedFinding(
            finding_id="policy:short-minimum-password-length", category="POLICY",
            rule="minimum-password-length", title=f"Minimum password length is {policy['minimum_password_length']}",
            affected_object=root, domain=workspace.domain,
            evidence={"canonical": policy, "raw": inventory.password_policy},
            status="single-source", priority="medium", workspace_artifacts=["inventory-comparison.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    for record in inventory.records.get("users", {}).values():
        for secret in extract_attribute_secret(record.attributes):
            account = record.attributes.get("sAMAccountName", record.identifier)
            if isinstance(account, list): account = account[0] if account else record.identifier
            ldap_secret_findings.append(NormalizedFinding(
                finding_id=f"ldap-secret:{record.identifier}:{secret['attribute']}:{secret['value']}",
                category="ACCOUNT", rule="ldap-attribute-secret",
                title=f"Credential stored in AD attribute — {account}",
                affected_object=record.identifier, domain=workspace.domain,
                sources=[{"source": source, "observed": True} for source in record.sources],
                evidence=secret, status="single-source", priority="high",
                workspace_artifacts=["LDAP/attributes.json"], first_seen_scan=workspace.scan_id,
                current_scan=workspace.scan_id).as_dict())
    cred1_findings = []
    cred1_output = sccm_result.get("cred1")
    cred1_items = cred1_output if isinstance(cred1_output, list) else ([cred1_output] if cred1_output else [])
    for cred1_item in cred1_items:
        for secret in cred1_item.get("credentials", []) or []:
            value = secret.get("value", secret.get("password", ""))
            if not value:
                continue
            name = secret.get("name", "") or "CRED-1 secret"
            digest = hashlib.sha256(str(value).encode()).hexdigest()[:16]
            cred1_findings.append(NormalizedFinding(
                finding_id=f"sccm-cred1:{cred1_item.get('dp', 'unknown')}:{name}:{digest}",
                category="SCCM", rule="CRED-1", title="CRED-1 — PXE boot media exposes credential material",
                affected_object=cred1_item.get("dp", "unknown"), domain=workspace.domain,
                sources=[{"source": "CinderPath", "observed": True}],
                evidence={"type": secret.get("type", "other"), "name": name,
                          "username": secret.get("username", ""), "value": value,
                          "source_policy": secret.get("source_policy", ""),
                          "task_sequence": secret.get("task_sequence", ""),
                          "dp": cred1_item.get("dp", ""), "site": cred1_item.get("site_code", ""),
                          "interface": cred1_item.get("interface", ""),
                          "wds": cred1_item.get("wds", "UNKNOWN"),
                          "boot_var": cred1_item.get("boot_var", "UNKNOWN"),
                          "media_identity": cred1_item.get("media_identity", "UNKNOWN"),
                          "assignment": cred1_item.get("assignment", "UNKNOWN"),
                          "policies": cred1_item.get("policies", 0),
                          "unique_secrets": len(cred1_item.get("credentials", []) or [])},
                status="confirmed", priority="high", workspace_artifacts=["SCCM/cred1.json"],
                first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    seen_credentials = set()
    for item in gpo_findings + ldap_secret_findings:
        value = item.get("evidence", {}).get("value")
        if not value:
            continue
        evidence = item.get("evidence", {})
        account = item.get("account") or evidence.get("username") or item.get("affected_object", "")
        key = (str(account).lower(), str(value), item.get("rule"))
        if key in seen_credentials:
            continue
        seen_credentials.add(key)
        discovered_credentials.append({"account": account or "UNKNOWN", "value": value,
                                       "type": evidence.get("type", item.get("rule")),
                                       "source": item.get("file") or evidence.get("attribute"),
                                       "context": item.get("gpo", {}).get("display_name") or item.get("title")})
    for item in cred1_findings:
        evidence = item["evidence"]
        key = (str(evidence.get("username") or evidence.get("name")).lower(),
               str(evidence.get("value")), "CRED-1")
        if key not in seen_credentials:
            seen_credentials.add(key)
            discovered_credentials.append({"account": evidence.get("username") or evidence.get("name"),
                                           "value": evidence["value"], "type": evidence.get("type", "other"),
                                           "source": evidence.get("source_policy") or "CinderPath",
                                           "context": f"CRED-1 PXE — {evidence.get('dp', '')}"})
    workspace.write_json(workspace.root / "credentials.json", discovered_credentials)
    workspace.write_text(workspace.root / "credentials.txt", "\n\n".join(
        f"Credential exposure — {x['context']}\n  Account: {x['account']}\n"
        f"  Value: {x['value']}\n  Type: {x['type']}\n  Source: {x['source']}"
        for x in discovered_credentials) + ("\n" if discovered_credentials else ""))
    kerberos_findings = []
    for item in exposures["asrep"]:
        state = "enabled" if item.enabled else "disabled"
        account_context = account_security_context(item, privileged=item.identifier in privileged_sids)
        kerberos_findings.append(NormalizedFinding(
            finding_id=f"kerberos:asrep:{item.identifier}", category="KERBEROS",
            rule="AS-REP-roastable", title=f"AS-REP roastable — {item.username} ({state})",
            affected_object=item.username, domain=workspace.domain,
            sources=[{"source": source, "observed": True} for source in item.sources],
            evidence={"enabled": item.enabled, "preauthentication_required": False,
                      "userAccountControl": item.attributes.get("userAccountControl"), **account_context},
            status="corroborated" if len(item.sources) > 1 else "single-source", priority="medium", workspace_artifacts=["Kerberos/inventory.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    for item in exposures["kerberoast"]:
        state = "enabled" if item.enabled else "disabled"
        account_context = account_security_context(item, privileged=item.identifier in privileged_sids)
        kerberos_findings.append(NormalizedFinding(
            finding_id=f"kerberos:spn:{item.identifier}", category="KERBEROS",
            rule="Kerberoastable-account", title=f"Kerberoastable — {item.username} ({state})",
            affected_object=item.username, domain=workspace.domain,
            sources=[{"source": source, "observed": True} for source in item.sources],
            evidence={"enabled": item.enabled, "spns": item.spns,
                      "userAccountControl": item.attributes.get("userAccountControl"),
                      "pwdLastSet": item.attributes.get("pwdLastSet"), **account_context},
            status="corroborated" if len(item.sources) > 1 else "single-source", priority="medium", workspace_artifacts=["Kerberos/inventory.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    for item in exposures["password_not_required"]:
        account_context = account_security_context(item, privileged=item.identifier in privileged_sids)
        kerberos_findings.append(NormalizedFinding(
            finding_id=f"account:passwd-not-required:{item.identifier}", category="ACCOUNT",
            rule="PASSWD_NOTREQD", title=f"Password not required — {item.username}", affected_object=item.username,
            domain=workspace.domain, sources=[{"source": source, "observed": True} for source in item.sources],
            evidence={"enabled": True, "userAccountControl": item.attributes.get("userAccountControl"), **account_context},
            status="corroborated" if len(item.sources) > 1 else "single-source", priority="medium", workspace_artifacts=["Kerberos/inventory.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    delegation_findings = []
    for item in delegation_records:
        if item.kind == "unconstrained" and item.expected_dc: continue
        delegation_findings.append(NormalizedFinding(
            finding_id=f"delegation:{item.kind}:{item.target}", category="DELEGATION", rule=item.kind,
            title=("RBCD" if item.kind == "rbcd" else
                   ("Constrained + protocol transition" if item.kind == "constrained" and item.protocol_transition else
                    f"{item.kind.replace('-', ' ').title()} delegation")) + f" — {item.target}", affected_object=item.target,
            domain=workspace.domain, sources=[{"source": source, "observed": True} for source in item.sources],
            evidence=item.as_dict(), status="corroborated" if len(item.sources) > 1 else "single-source", priority="medium",
            workspace_artifacts=["Delegation/inventory.json"], first_seen_scan=workspace.scan_id,
            current_scan=workspace.scan_id).as_dict())
    for host in inventory.records.get("observed_hosts", {}).values():
        if host.attributes.get("smb_signing") is False:
            relay_findings.append(NormalizedFinding(
                finding_id=f"relay:smb-signing:{host.identifier}", category="RELAY",
                rule="SMB-signing-not-required", title=f"SMB signing not required — {host.attributes.get('host', host.identifier)}",
                affected_object=host.identifier, domain=workspace.domain,
                sources=[{"source": source} for source in host.sources],
                evidence={"host": host.attributes, "impact": "relay prerequisite"},
                status="single-source", priority="medium", workspace_artifacts=["Relay/relay-targets.txt"],
                first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    workspace.write_json(workspace.findings_path("LDAP", "findings.json"), policy_findings + description_findings + ldap_secret_findings)
    workspace.write_json(workspace.findings_path("LDAP", "attributes.json"), ldap_secret_findings)
    workspace.write_json(workspace.findings_path("Kerberos", "findings.json"), kerberos_findings)
    workspace.write_json(workspace.findings_path("Delegation", "findings.json"), delegation_findings)
    for item in gpo_findings:
        gpo_finding = NormalizedFinding(
            finding_id=f"gpo:{item['rule']}:{item['gpo'].get('guid')}:{item['file']}",
            category="GPO", rule=item["rule"], title=item["title"],
            affected_object=item["gpo"].get("guid", item["file"]), domain=workspace.domain,
            sources=[{"source": "sysvol", "observed": True}],
            evidence={**item["evidence"], "file": item.get("file"), "account": item.get("account"),
                      "gpo": item.get("gpo", {}).get("display_name")},
            status="single-source", priority="high", workspace_artifacts=["GPO/findings.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id)
        item["normalized"] = gpo_finding.as_dict()
    # Keep inactive SPN accounts in Kerberos inventory/evidence, but do not
    # present them as active exposure findings in the operator overview.
    active_kerberos_findings = [x for x in kerberos_findings
                                if not (x.get("rule") == "Kerberoastable-account"
                                        and x.get("evidence", {}).get("enabled") is False)]
    all_findings = (finding_records + policy_findings + description_findings + ldap_secret_findings + cred1_findings + active_kerberos_findings +
                    domain_security_findings +
                    delegation_findings + relay_findings + smb_findings + acl_findings +
                    ldap_security_findings + anonymous_smb_findings + [x["normalized"] for x in gpo_findings])
    workspace.write_json(workspace.findings_path("vulnerabilities", "findings.json"), all_findings)
    workspace.write_text(workspace.findings_path("vulnerabilities", "findings.txt"),
                          "\n".join(f"[{x['category']}] {x['title']}" for x in all_findings) + "\n")
    workspace.write_json(workspace.root / "external-results.json", external_results)
    published = set()
    for t, ca, native in findings:
            published.add(t.name)
            vulnerable, reasons = native.vulnerable, native.detail.split("; ") if native.detail else []
            if a.verbose:
                console.debug_line(f"template={t.name} flags=0x{t.name_flags:x}/0x{t.enrollment_flags:x} ekus={t.ekus} application_policies={t.application_policies}")
                for ace in t.security_descriptor or []: console.debug_line(f"ACE type={ace.ace_type} kind={ace.kind} sid={ace.sid} mask=0x{ace.mask:x} object_type={ace.object_type} inherited={ace.inherited}")
            elif a.verbose:
                console.debug_line(f"template={t.name} CA={ca.name} result=NOT ESC1 rejected because: {'; '.join(reasons)}")
    if a.verbose:
        for t in templates:
            if t.name not in published:
                from .rules import classify_esc1
                from .models import PrincipalContext, CA
                principals = PrincipalContext(set().union(*(x.evidence.get("low_privileged_subject_sids", set()) for x in templates)))
                _, reasons = classify_esc1(t, CA("", ""), principals, False)
                console.debug_line(f"template={t.name} result=NOT ESC1 rejected because: {'; '.join(reasons)}")
        for ca, ref in dangling: console.debug_line(f"dangling publication: CA={ca} template={ref}")
        for key, values in duplicates.items(): console.debug_line(f"duplicate template key={key} count={len(values)}")
        console.line(coverage.render("Coverage"))
    if certipy and a.verbose:
        for name, comparison in comparisons.items():
            if len(comparison.assessments) > 1:
                console.line(f"[CORROBORATION] {name}: {comparison.status}")
                if comparison.status == "disagreement":
                    for assessment in comparison.assessments:
                        console.line(f"  {assessment.source}: {assessment.vulnerable} ({assessment.detail})")
    statuses = [c for c in comparisons.values() if c.status == "corroborated"]
    disagreements = [c for c in comparisons.values() if c.status == "disagreement"]
    summary = (f"Domain: {root}\nTarget: {target}\n\nADCS\n  CAs: {len(cas)}\n"
               f"  Templates: {len(templates)}\n  Native ESC1 findings: "
               f"{sum(1 for _, _, x in findings if x.vulnerable)}\n"
               f"  Corroborated: {len(statuses)}\n  Disagreements: {len(disagreements)}\n\n"
               "Domain inventory\n" + "\n".join(f"  {key}: {value}" for key, value in inventory.counts().items()) + "\n\n"
               f"Users with descriptions: {sum(bool(r.attributes.get('description')) for r in inventory.records.get('users', {}).values())}\n\n"
               f"Credential-like descriptions: {len(description_findings)}\n\n"
               f"Password policy source: {inventory.password_policy.get('source', 'unavailable')}\n\n"
               f"Hosts discovered: {len(context.targets)}; SMB observations: {len(inventory.records.get('observed_hosts', {}))}\n\n"
               f"Kerberos exposures: AS-REP={len(exposures['asrep'])}; SPN={len(exposures['kerberoast'])}\n"
               f"Delegation: unconstrained non-DC={sum(x.kind == 'unconstrained' and not x.expected_dc for x in delegation_records)}; "
               f"constrained={sum(x.kind == 'constrained' for x in delegation_records)}; RBCD={sum(x.kind == 'rbcd' for x in delegation_records)}\n\n"
               "Execution plan\n" + "\n".join(f"  {item.spec.name}: {item.status.value}"
                                               + (f" ({item.reason})" if item.reason else "") for item in plan) + "\n\n"
               f"{coverage.render()}\n")
    workspace.write_text(workspace.root / "summary.txt", summary)
    report_text = _results_text(root, target, external_results, inventory, cas, templates, all_findings,
                                workspace, corroborated=len(statuses), disagreements=len(disagreements),
                                smb_shares=share_inventory, services=service_inventory,
                                access_records=access_records, cred1=sccm_result.get("cred1"),
                                host_identities=dns_map)
    workspace.write_text_atomic(workspace.root / "results.txt", report_text)
    # Keep a non-destructive historical copy for this scan ID.
    workspace.write_json(workspace.history_root / "scan.json", {"domain": root, "target": target,
                                                                  "scan_id": workspace.scan_id})
    workspace.write_json(workspace.history_root / "coverage.json", coverage.as_dict())
    workspace.write_text(workspace.history_root / "results.txt", report_text)
    if a.html_out:
        try:
            counts = inventory.counts()
            html_model = {
                "domain": root, "target": target, "workspace": f"{workspace.domain}/",
                "banner": files("ad_enum").joinpath("assets/banner.txt").read_text(encoding="utf-8") + "\n@Evilhaxxor",
                "category_order": CATEGORY_ORDER, "findings": all_findings,
                "collectors": {"Native LDAP": "PASS", **{
                    label: {"PASS": "PASS", "FAILED": "FAILED", "UNAVAILABLE": "NOT AVAILABLE"}.get(
                        external_results.get(module_id, {}).get("status", "NOT CHECKED"),
                        external_results.get(module_id, {}).get("status", "NOT CHECKED"))
                    for module_id, label in (("bloodhound", "BloodHound"), ("adcs-certipy", "Certipy"),
                                              ("ldapdomaindump", "LDAPDomainDump"), ("netexec", "NetExec"))}},
                "inventory": {"Users": counts.get("users", 0), "Groups": counts.get("groups", 0),
                              "Computers": counts.get("computers", 0),
                              "Domain Controllers": counts.get("domain_controllers", 0),
                              "Domains": counts.get("domains", 0), "gMSAs": counts.get("gmsa", 0),
                              "CAs": len(cas), "Templates": len(templates)},
                "credentials": discovered_credentials,
                "smb_shares": share_inventory,
                "services": service_inventory,
                "access": access_records,
                "sccm": {key: sccm_result.get(key, []) for key in
                          ("site_code", "management_points", "distribution_points", "site_servers",
                           "sms_providers", "sql_servers", "sup_wsus", "pxe", "cred1", "status")},
                "coverage": coverage.as_dict(),
            }
            write_html_report(a.html_out, html_model)
            console.line(Console.field("HTML report", a.html_out))
        except Exception as exc:
            console.complete(f"HTML report generation failed: {type(exc).__name__}: {exc}", "WARNING")
    history_adcs = workspace.history_module_dir("ADCS")
    workspace.write_json(history_adcs / "findings.json", finding_records)
    workspace.write_json(history_adcs / "raw" / "ldap.json", collector.raw)
    if certipy:
        workspace.write_json(history_adcs / "raw" / "certipy.json", certipy.raw_data)
    workspace.write_text(history_adcs / "findings.txt",
                          "\n".join(f"[{x['status']}] {x['title']}" for x in finding_records) + "\n")
    # Preserve every generated adapter artifact in the scan history.  The
    # current module directory remains the convenient latest view.
    for item in plan:
        if item.spec.outputs and item.status.value == "READY":
            source_dir = workspace.module_dir(item.spec.outputs[0])
            if source_dir.exists():
                shutil.copytree(source_dir, workspace.history_module_dir(item.spec.outputs[0]),
                                dirs_exist_ok=True)
    console.activity("Correlating findings...")
    console.complete("Analysis complete")
    console.line()
    console.heading("Target")
    console.line(f"  Domain ............. {root}")
    console.line(f"  DC ................. {target}")
    console.line()
    console.heading("Collectors")
    console.status(Console.field("Native LDAP", "PASS"), "PASS")
    for module_id, label in (("bloodhound", "BloodHound"), ("adcs-certipy", "Certipy"),
                             ("ldapdomaindump", "LDAPDomainDump"), ("netexec", "NetExec")):
        result = external_results.get(module_id, {})
        state = result.get("status", "NOT CHECKED")
        display = {"PASS": "PASS", "FAILED": "FAILED", "UNAVAILABLE": "NOT AVAILABLE"}.get(state, state)
        console.status(Console.field(label, display), display)
    console.line()
    console.heading("Inventory")
    for key, label in (("users", "Users"), ("groups", "Groups"), ("computers", "Computers"),
                       ("domain_controllers", "Domain Controllers"), ("domains", "Domains"),
                       ("gmsa", "gMSAs")):
        console.line(Console.field(label, inventory.counts().get(key, 0)))
    console.line(Console.field("CAs", len(cas)))
    console.line(Console.field("Templates", len(templates)))
    if share_inventory:
        console.line()
        console.heading("SMB Share Access")
        for line in _smb_share_access_lines(share_inventory):
            console.line(line)
    service_lines = _service_summary_lines(service_inventory, host_identities=dns_map)
    if service_lines:
        console.line()
        console.heading("Service Exposure")
        for line in service_lines:
            console.line(line)
    access_lines = _access_summary_lines(access_records, host_identities=dns_map)
    if access_lines:
        console.line()
        console.heading("Authenticated Access")
        for line in access_lines:
            console.line(line)
    cred1_output = sccm_result.get("cred1")
    if cred1_output:
        console.line()
        console.heading("SCCM CRED-1 PXE")
        cred1_items = cred1_output if isinstance(cred1_output, list) else [cred1_output]
        for index, item in enumerate(cred1_items):
            if index:
                console.line()
            for line in _cred1_summary_lines(item, indent="  "):
                console.line(line)
    console.line()
    console.heading("Findings")
    if not all_findings:
        console.line("  None")
    else:
        category_order = ("ADCS", "POLICY", "KERBEROS", "ACCOUNT", "DELEGATION",
                          "GPO", "ACL", "LAPS", "LDAP", "SMB", "RELAY", "SCCM", "TRUSTS")
        grouped = {category: [] for category in category_order}
        for item in all_findings:
            # Disabled Kerberoastable principals remain in JSON evidence, but
            # should not look like currently actionable findings in normal UI.
            if (item.get("rule") == "Kerberoastable-account"
                    and item.get("title", "").endswith("(disabled)")):
                continue
            grouped.setdefault(item.get("category", "OTHER"), []).append(item)
        for category in category_order + tuple(x for x in grouped if x not in category_order):
            items = grouped.get(category, [])
            if not items: continue
            console.category_header(category)
            for item in items:
                display_status = item.get("status")
                if item.get("rule") == "ESC1" and display_status in {"disagreement", "live-confirmed disagreement"}:
                    display_status = "confirmed"
                title = item["title"]
                evidence = item.get("evidence", {})
                if item.get("category") == "ACL":
                    title = f"Account control — {item.get('affected_object', title)}"
                console.status(f"  {title}", display_status)
                objects = _affected_object_values(item, limit=10)
                if objects:
                    console.line("    Affected objects")
                    for value in objects:
                        console.line(f"      {value}")
                if item["rule"] == "ESC1":
                    fields = [("Status", display_status.upper())]
                    if item.get("status") in {"disagreement", "live-confirmed disagreement"}:
                        fields.append(("Note", "Certipy did not classify this template as ESC1"))
                    for line in _compact_field_lines(fields, indent="    "):
                        console.line(line)
                elif item["rule"] == "Kerberoastable-account":
                    for line in _compact_field_lines([
                            ("State", "enabled" if evidence.get("enabled") else "disabled"),
                            ("SPNs", len(evidence.get("spns", []))),
                            ("Status", item.get("status", "").upper()),
                    ], indent="    "):
                        console.line(line)
                elif item.get("category") == "ACL":
                    for line in _compact_field_lines([
                            ("Principal", evidence.get("principal_sid", "unknown")),
                            ("Rights", evidence.get("effective_rights", "")),
                            ("Impact", "Low-privileged principal can alter or control this object"),
                    ], indent="    "):
                        console.line(line)
                elif item.get("category") == "DELEGATION" and item.get("rule") == "rbcd":
                    for line in _compact_field_lines([
                            ("Allowed principal", evidence.get("principal_name") or evidence.get("principal_sid", "unknown")),
                            ("Impact", evidence.get("impact", "May impersonate users to Kerberos services on the target")),
                    ], indent="    "):
                        console.line(line)
                elif item.get("rule", "").startswith("gpo-"):
                    fields = []
                    if evidence.get("file"): fields.append(("File", evidence["file"]))
                    if evidence.get("account"): fields.append(("Account", evidence["account"]))
                    if evidence.get("type"): fields.append(("Type", evidence["type"]))
                    if evidence.get("value"):
                        fields.append(("cpassword" if item.get("rule") == "gpp-cpassword" else "Value", evidence["value"]))
                    for line in _compact_field_lines(fields, indent="    "):
                        console.line(line)
                elif item.get("status") not in {"single-source", "corroborated"}:
                    for line in _compact_field_lines([("Status", item.get("status", "").upper())], indent="    "):
                        console.line(line)
    console.line()
    console.heading("Workspace")
    console.line(console.paint(f"  {workspace.domain}/", "dim"))
    if collector.kerberos_session:
        collector.kerberos_session.close()
    return 0
