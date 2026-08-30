import argparse
import sys
import ipaddress
import shutil
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
                        parse_netexec_smb, extract_attribute_secret)
from .sccm import discover as discover_sccm, normalize_relayking, probe_management_points
from .network import build_dns_map
from .dns_enum import normalize_zones, normalize_records, merge_into_dns_map, normalize_password_settings
from .gpo import normalize_gpos, collect_sysvol, collect_netlogon, inspect_file, parse_security_settings
from .posture import (normalize_smb, normalize_trusts, normalize_gpo_acls, normalize_laps,
                      attach_gpo_links, normalize_security_descriptors, analyze_effective_acls)
from .kerberos import roastable, account_exposure, privileged_account_sids, account_security_context
from .delegation import enumerate_delegation, enumerate_gmsa
from .core.console import Console


CATEGORY_ORDER = ("ADCS", "POLICY", "KERBEROS", "ACCOUNT", "DELEGATION",
                  "GPO", "ACL", "LAPS", "LDAP", "SMB", "RELAY", "SCCM", "TRUSTS")


def _finding_lines(findings):
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
            evidence = item.get("evidence", {}) or {}
            title = item.get("title", "")
            if category == "ACL":
                title = f"Account control — {item.get('affected_object', title)}"
            lines.append(title)
            if item.get("rule") == "ESC1":
                lines.append(f"  Status ........... {status}")
                if item.get("status") in {"disagreement", "live-confirmed disagreement"}:
                    lines.append("  Note ............. Certipy did not classify this template as ESC1")
            elif item.get("rule") == "Kerberoastable-account":
                lines.extend([f"  State ............ {'enabled' if evidence.get('enabled') else 'disabled'}",
                              f"  SPNs ............. {len(evidence.get('spns', []))}",
                              f"  Status ........... {item.get('status', '').upper()}" ])
                for label in ("Privileged", "Service account", "Password age"):
                    key = {"Privileged": "privileged", "Service account": "service_account",
                           "Password age": "password_age"}[label]
                    if key in evidence:
                        lines.append(f"  {label:<18} {evidence[key]}")
            elif category == "ACL":
                lines.extend([f"  Principal ........ {evidence.get('principal_sid', 'unknown')}",
                              f"  Rights ........... {evidence.get('effective_rights', '')}",
                              "  Impact ........... Low-privileged principal can alter or control this object"])
            elif category == "DELEGATION" and item.get("rule") == "rbcd":
                lines.extend([f"  Allowed principal  {evidence.get('principal_name') or evidence.get('principal_sid', 'unknown')}",
                              f"  Impact ........... {evidence.get('impact', 'May impersonate users to Kerberos services on the target')}"])
            elif item.get("rule", "").startswith("gpo-"):
                if evidence.get("file"): lines.append(f"  File ............. {evidence['file']}")
                if evidence.get("account"): lines.append(f"  Account .......... {evidence['account']}")
                if evidence.get("type"): lines.append(f"  Type ............. {evidence['type']}")
                if evidence.get("value"):
                    label = "cpassword" if item.get("rule") == "gpp-cpassword" else "Value"
                    lines.append(f"  {label:<18} {evidence['value']}")
            elif status:
                lines.append(f"  Status ........... {status}")
            lines.append("")
    return lines


def _results_text(root, target, external_results, inventory, cas, templates, all_findings,
                  workspace, *, corroborated=0, disagreements=0):
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
                  Console.field("Disagreements", disagreements), "", "Findings"])
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
    p.add_argument("--timeout", type=float, default=10)
    p.add_argument("--modules", default="all", help="comma-separated modules (default: all read-only collectors)")
    p.add_argument("--profile", default="default")
    p.add_argument("--certipy-json", help="optional Certipy -json result for corroboration")
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
        console.complete(f"Target resolved: {target}")
    except Exception as exc:
        failure = translate_kerberos_error(exc) if a.force_kerb else None
        if failure and failure.category != "bad-credentials":
            console.status(failure.message, "FAILED")
            if failure.hint: console.line(f"  {failure.hint}")
            if a.verbose: console.debug_line(f"Raw Kerberos error: {failure.raw}")
        else:
            console.status("Credentials Invalid", "INVALID")
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
    def report_progress(stage, label, state=None):
        if stage == "start": console.activity(f"Running {label}...")
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
    workspace.write_json(workspace.findings_path("PasswordPolicies", "inventory.json"),
                         normalize_password_settings(collector.raw.get("password_settings", [])))
    workspace.write_json(workspace.findings_path("PasswordPolicies", "findings.json"), [])
    workspace.write_text(workspace.module_dir("PasswordPolicies") / "findings.txt", "")
    coverage.add("AD DNS / integrated records", "PASS", f"{len(dns_zones)} zone(s), {len(dns_records)} record(s)")
    coverage.add("Password policies / FGPP", "PASS", f"{len(collector.raw.get('password_settings', []))} PSO(s)")
    console.activity("Checking LDAP security...")
    smb_inventory, smb_findings = [], []
    trust_inventory = normalize_trusts(collector.raw.get("trusts", []))
    workspace.write_json(workspace.findings_path("Trusts", "inventory.json"), trust_inventory)
    workspace.write_json(workspace.findings_path("Trusts", "findings.json"), [])
    workspace.write_text(workspace.module_dir("Trusts") / "findings.txt", "")
    ldap_security = {"signing": {"state": "UNKNOWN", "evidence": [],
                                  "reason": "no direct unsigned-bind policy/protocol observation"},
                     "channel_binding": {"state": "UNKNOWN", "evidence": [],
                                          "reason": "LDAPS channel binding cannot be assessed without a valid TLS service"}}
    ldap_security_findings = []
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
    findings, comparisons, coverage, dangling, duplicates = scan(cas, templates, certipy=certipy)
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
    privileged_sids = privileged_account_sids(inventory)
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
        if share.get("writable"):
            smb_findings.append(NormalizedFinding(
                finding_id=f"smb:writable-share:{share.get('ip')}:{share.get('share')}", category="SMB",
                rule="writable-share", title=f"Low-privilege writable share — {share.get('host') or share.get('ip')}\\{share.get('share')}",
                affected_object=share.get("unc", share.get("share", "unknown")), domain=workspace.domain,
                sources=[{"source": source, "observed": True} for source in share.get("sources", [])],
                evidence={"share": share, "impact": "Low-privileged users can modify share content"},
                status="single-source", priority="medium", workspace_artifacts=["SMB/shares.json"],
                first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    workspace.write_json(workspace.findings_path("SMB", "findings.json"), smb_findings)
    workspace.write_text(workspace.module_dir("SMB") / "findings.txt", "\n".join(f"[{x['category']}] {x['title']}" for x in smb_findings) + ("\n" if smb_findings else ""))
    coverage.add("SMB / share inventory", "PASS" if share_inventory else "PARTIAL", f"{len(share_inventory)} share(s)")
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
    workspace.write_json(workspace.findings_path("SCCM", "topology.json"), sccm_result)
    workspace.write_json(workspace.raw_dir("SCCM") / "ldap-publication.json", collector.raw.get("sccm", []))
    workspace.write_json(workspace.findings_path("SCCM", "endpoints.json"), sccm_result.get("endpoint_probes", []))
    workspace.write_json(workspace.findings_path("SCCM", "pxe.json"), sccm_result.get("pxe", {}))
    coverage.add("SCCM / infrastructure discovery", "PASS", f"{len(sccm_result['hosts'])} candidate host(s)")
    console.complete("SCCM analysis complete")
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
    coverage.add("GPO / security settings", "PARTIAL", f"{len(gpo_security_settings)} setting observation(s)")
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
    discovered_credentials = []
    seen_credentials = set()
    for item in gpo_findings + ldap_secret_findings:
        value = item.get("evidence", {}).get("value")
        if not value: continue
        evidence = item.get("evidence", {})
        account = item.get("account") or evidence.get("username") or item.get("affected_object", "")
        key = (str(account).lower(), str(value), item.get("rule"))
        if key in seen_credentials: continue
        seen_credentials.add(key)
        discovered_credentials.append({"account": account or "UNKNOWN",
                                       "value": value,
                                       "type": evidence.get("type", item.get("rule")),
                                       "source": item.get("file") or evidence.get("attribute"),
                                       "context": item.get("gpo", {}).get("display_name") or item.get("title")})
    workspace.write_json(workspace.root / "credentials.json", discovered_credentials)
    workspace.write_text(workspace.root / "credentials.txt", "\n\n".join(
        f"Credential exposure — {x['context']}\n  Account: {x['account']}\n"
        f"  Value: {x['value']}\n  Type: {x['type']}\n  Source: {x['source']}"
        for x in discovered_credentials) + ("\n" if discovered_credentials else ""))
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
        "domain": root, "canonical_domain": workspace.domain, "target": target,
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
    policy_findings = []
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
    description_findings = []
    ldap_secret_findings = []
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
    all_findings = (finding_records + policy_findings + description_findings + ldap_secret_findings + active_kerberos_findings +
                    domain_security_findings +
                    delegation_findings + relay_findings + smb_findings + acl_findings +
                    ldap_security_findings + [x["normalized"] for x in gpo_findings])
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
                                workspace, corroborated=len(statuses), disagreements=len(disagreements))
    workspace.write_text_atomic(workspace.root / "results.txt", report_text)
    # Keep a non-destructive historical copy for this scan ID.
    workspace.write_json(workspace.history_root / "scan.json", {"domain": root, "target": target,
                                                                  "scan_id": workspace.scan_id})
    workspace.write_json(workspace.history_root / "coverage.json", coverage.as_dict())
    workspace.write_text(workspace.history_root / "results.txt", report_text)
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
                if item["rule"] == "ESC1":
                    console.line(f"    Status ........... {display_status.upper()}")
                    if item.get("status") in {"disagreement", "live-confirmed disagreement"}:
                        console.line("    Note ............. Certipy did not classify this template as ESC1")
                elif item["rule"] == "Kerberoastable-account":
                    console.line(f"    State ............ {'enabled' if evidence.get('enabled') else 'disabled'}")
                    console.line(f"    SPNs ............. {len(evidence.get('spns', []))}")
                    console.line(f"    Status ........... {item.get('status', '').upper()}")
                elif item.get("category") == "ACL":
                    console.line(f"    Principal ........ {evidence.get('principal_sid', 'unknown')}")
                    console.line(f"    Rights ........... {evidence.get('effective_rights', '')}")
                    console.line("    Impact ........... Low-privileged principal can alter or control this object")
                elif item.get("category") == "DELEGATION" and item.get("rule") == "rbcd":
                    console.line(f"    Allowed principal  {evidence.get('principal_name') or evidence.get('principal_sid', 'unknown')}")
                    console.line(f"    Impact ........... {evidence.get('impact', 'May impersonate users to Kerberos services on the target')}")
                elif item.get("rule", "").startswith("gpo-"):
                    if evidence.get("file"): console.line(f"    File ............. {evidence['file']}")
                    if evidence.get("account"): console.line(f"    Account .......... {evidence['account']}")
                    if evidence.get("type"): console.line(f"    Type ............. {evidence['type']}")
                    if evidence.get("value"): console.line(f"    {'cpassword' if item.get('rule') == 'gpp-cpassword' else 'Value'} ............ {evidence['value']}")
                elif item.get("status") not in {"single-source", "corroborated"}:
                    console.line(f"    Status ........... {item.get('status', '').upper()}")
    console.line()
    console.heading("Workspace")
    console.line(console.paint(f"  {workspace.domain}/", "dim"))
    if collector.kerberos_session:
        collector.kerberos_session.close()
    return 0
