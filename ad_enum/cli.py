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
from .inventory import native_inventory, DomainInventory, build_targets, sensitive_description, parse_netexec_smb
from .sccm import discover as discover_sccm, normalize_relayking, probe_management_points
from .network import build_dns_map
from .gpo import normalize_gpos, collect_sysvol, collect_netlogon, inspect_file
from .posture import (normalize_smb, normalize_trusts, normalize_gpo_acls, normalize_laps,
                      attach_gpo_links, normalize_security_descriptors, analyze_effective_acls)
from .kerberos import roastable
from .delegation import enumerate_delegation, enumerate_gmsa
from .core.console import Console


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
        root, _ = collector.preflight()
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
    root, cas, templates = collector.collect()
    context.kerberos_session = collector.kerberos_session
    inventory = native_inventory(collector.raw)
    native_counts = inventory.counts()
    context.targets = build_targets(inventory)
    external_results, external_diagnostics = execute_external(context, plan, certipy_snapshot=imported_certipy)
    certipy_result = external_results.get("adcs-certipy", {}).get("snapshot") if external_results.get("adcs-certipy", {}).get("status") == "PASS" else None
    certipy = certipy_result or imported_certipy
    source_counts = {"native-ldap": native_counts}
    for result in external_results.values():
        obj = result.get("result", {}) if isinstance(result, dict) else {}
        if hasattr(obj.get("inventory") if isinstance(obj, dict) else None, "records"):
            inventory.merge(obj["inventory"])
    networkhound_result = external_results.get("networkhound", {}).get("result", {})
    dns_map = build_dns_map(inventory, networkhound_result.get("inventory") if isinstance(networkhound_result, dict) else None)
    workspace.write_json(workspace.root / "dns-map.json", dns_map)
    workspace.write_json(workspace.findings_path("LDAP", "networking.json"),
                         {"sites": collector.raw.get("sites", []), "subnets": collector.raw.get("subnets", [])})
    workspace.write_json(workspace.findings_path("NetworkHound", "inventory.json"),
                         networkhound_result.get("inventory", {}) if isinstance(networkhound_result, dict) else {})
    workspace.write_json(workspace.findings_path("NetworkHound", "dns-map.json"), dns_map)
    smb_inventory, smb_findings = [], []
    trust_inventory = normalize_trusts(collector.raw.get("trusts", []))
    workspace.write_json(workspace.findings_path("Trusts", "inventory.json"), trust_inventory)
    workspace.write_json(workspace.findings_path("Trusts", "findings.json"), [])
    workspace.write_text(workspace.module_dir("Trusts") / "findings.txt", "")
    ldap_security = {"signing": {"state": "UNKNOWN", "evidence": [],
                                  "reason": "no direct unsigned-bind policy/protocol observation"},
                     "channel_binding": {"state": "UNKNOWN", "evidence": [],
                                          "reason": "LDAPS channel binding cannot be assessed without a valid TLS service"}}
    workspace.write_json(workspace.findings_path("LDAPSecurity", "inventory.json"), ldap_security)
    workspace.write_json(workspace.findings_path("LDAPSecurity", "findings.json"), [])
    workspace.write_text(workspace.module_dir("LDAPSecurity") / "findings.txt", "")
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
    workspace.write_json(workspace.findings_path("SMB", "inventory.json"), smb_inventory)
    unsigned = [x for x in smb_inventory if x.get("smb_signing") is False]
    if unsigned:
        smb_findings.append(NormalizedFinding(
            finding_id="smb:signing-not-required", category="SMB", rule="signing-not-required",
            title=f"SMB signing not required — {len(unsigned)} host(s)", affected_object=workspace.domain,
            domain=workspace.domain, sources=[{"source": source, "observed": True} for source in sorted({s for x in unsigned for s in x["sources"]})],
            evidence={"hosts": unsigned}, status="single-source", priority="medium",
            workspace_artifacts=["SMB/inventory.json"], first_seen_scan=workspace.scan_id,
            current_scan=workspace.scan_id).as_dict())
    workspace.write_json(workspace.findings_path("SMB", "findings.json"), smb_findings)
    workspace.write_text(workspace.module_dir("SMB") / "findings.txt", "\n".join(f"[{x['category']}] {x['title']}" for x in smb_findings) + ("\n" if smb_findings else ""))
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
    expected_acl_principals = {
        str(record.identifier) for record in inventory.records.get("users", {}).values()
        if str((record.attributes.get("sAMAccountName", [""])[0]
                if isinstance(record.attributes.get("sAMAccountName", [""]), list)
                else record.attributes.get("sAMAccountName", ""))).lower() == str(a.username).lower()
    }
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
    gpo_by_guid = {str(g.get("guid", "")).strip("{}").lower(): g for g in gpos}
    for item in sysvol.get("files", []):
        gpo = gpo_by_guid.get(str(item.get("gpo_guid", "")).strip("{}").lower(), {"guid": item.get("gpo_guid")})
        gpo_findings.extend(inspect_file(gpo, item["path"], item["content"]))
        safe = dict(item); safe.pop("content", None)
        workspace.write_json(workspace.raw_dir("GPO") / (str(item["gpo_guid"]).strip("{}").lower() + ".json"), safe)
    workspace.write_json(workspace.findings_path("GPO", "inventory.json"), gpos)
    workspace.write_json(workspace.findings_path("GPO", "links.json"), collector.raw.get("gpo_links", []))
    workspace.write_json(workspace.findings_path("GPO", "acl.json"), gpo_acls)
    workspace.write_json(workspace.findings_path("GPO", "effective-rights.json"), gpo_acl_observations)
    workspace.write_json(workspace.findings_path("GPO", "policies.json"), {"status": sysvol.get("status"), "error": sysvol.get("error", ""), "files": [{k: v for k, v in x.items() if k != "content"} for x in sysvol.get("files", [])]})
    workspace.write_json(workspace.findings_path("GPO", "findings.json"), gpo_findings)
    sysvol_dir = workspace.module_dir("GPO") / "SYSVOL"
    workspace.write_json(sysvol_dir / "inventory.json",
                         [{"gpo_guid": x.get("gpo_guid"), "path": x.get("path"), "name": x.get("name"),
                           "size": len(x.get("content", b"")), "inspection_status": "INSPECTED"}
                          for x in sysvol.get("files", [])])
    workspace.write_json(sysvol_dir / "findings.json", gpo_findings)
    workspace.write_text(workspace.module_dir("GPO") / "findings.txt",
                         "\n\n".join(f"[GPO] {x['title']}\n  File: {x['file']}\n  Account: {x['account']}" for x in gpo_findings) + ("\n" if gpo_findings else ""))
    workspace.write_json(workspace.module_dir("GPO") / "NETLOGON" / "inventory.json", netlogon)
    coverage.add("GPO / LDAP inventory", "PASS", f"{len(gpos)} group policy object(s)")
    gpo_status = {"PASS": "PASS", "FAILED": "FAILED", "UNAVAILABLE": "NOT AVAILABLE"}.get(sysvol.get("status"), "FAILED")
    coverage.add("GPO / SYSVOL targeted inspection", gpo_status, f"{len(sysvol.get('files', []))} file(s)")
    netlogon_status = {"PASS": "PASS", "FAILED": "FAILED", "UNAVAILABLE": "NOT AVAILABLE"}.get(netlogon.get("status"), "FAILED")
    coverage.add("GPO / NETLOGON targeted inventory", netlogon_status, f"{len(netlogon.get('files', []))} file(s)")
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
    workspace.write_json(workspace.findings_path("ACL", "findings.json"), acl_findings)
    workspace.write_text(workspace.module_dir("ACL") / "findings.txt",
                         "\n".join(f"[{x['category']}] {x['title']}" for x in acl_findings) +
                         ("\n" if acl_findings else ""))
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
                      "coverage": "coverage.json", "summary": "summary.txt"}
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
    for record in inventory.records.get("users", {}).values():
        description = record.attributes.get("description")
        if sensitive_description(description):
            description_findings.append(NormalizedFinding(
                finding_id=f"user-description:{record.identifier}", category="INVENTORY",
                rule="sensitive-user-description", title="Credential-like user description",
                affected_object=record.identifier, domain=workspace.domain,
                sources=[{"source": source} for source in record.sources],
                evidence={"description": "<redacted credential-like value>", "signals": ["credential marker"]},
                status="single-source", priority="medium", workspace_artifacts=["inventory.json"],
                first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    kerberos_findings = []
    for item in exposures["asrep"]:
        state = "enabled" if item.enabled else "disabled"
        kerberos_findings.append(NormalizedFinding(
            finding_id=f"kerberos:asrep:{item.identifier}", category="KERBEROS",
            rule="AS-REP-roastable", title=f"AS-REP roastable — {item.username} ({state})",
            affected_object=item.username, domain=workspace.domain,
            sources=[{"source": source, "observed": True} for source in item.sources],
            evidence={"enabled": item.enabled, "preauthentication_required": False,
                      "userAccountControl": item.attributes.get("userAccountControl")},
            status="corroborated" if len(item.sources) > 1 else "single-source", priority="medium", workspace_artifacts=["Kerberos/inventory.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    for item in exposures["kerberoast"]:
        state = "enabled" if item.enabled else "disabled"
        kerberos_findings.append(NormalizedFinding(
            finding_id=f"kerberos:spn:{item.identifier}", category="KERBEROS",
            rule="Kerberoastable-account", title=f"Kerberoastable — {item.username} ({state})",
            affected_object=item.username, domain=workspace.domain,
            sources=[{"source": source, "observed": True} for source in item.sources],
            evidence={"enabled": item.enabled, "spns": item.spns,
                      "userAccountControl": item.attributes.get("userAccountControl"),
                      "pwdLastSet": item.attributes.get("pwdLastSet")},
            status="corroborated" if len(item.sources) > 1 else "single-source", priority="medium", workspace_artifacts=["Kerberos/inventory.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    for item in exposures["password_not_required"]:
        kerberos_findings.append(NormalizedFinding(
            finding_id=f"account:passwd-not-required:{item.identifier}", category="ACCOUNT",
            rule="PASSWD_NOTREQD", title=f"Password not required — {item.username}", affected_object=item.username,
            domain=workspace.domain, sources=[{"source": source, "observed": True} for source in item.sources],
            evidence={"enabled": True, "userAccountControl": item.attributes.get("userAccountControl")},
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
    workspace.write_json(workspace.findings_path("LDAP", "findings.json"), policy_findings + description_findings)
    workspace.write_json(workspace.findings_path("Kerberos", "findings.json"), kerberos_findings)
    workspace.write_json(workspace.findings_path("Delegation", "findings.json"), delegation_findings)
    for item in gpo_findings:
        gpo_finding = NormalizedFinding(
            finding_id=f"gpo:{item['rule']}:{item['gpo'].get('guid')}:{item['file']}",
            category="GPO", rule=item["rule"], title=item["title"],
            affected_object=item["gpo"].get("guid", item["file"]), domain=workspace.domain,
            sources=[{"source": "sysvol", "observed": True}], evidence=item["evidence"],
            status="single-source", priority="high", workspace_artifacts=["GPO/findings.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id)
        item["normalized"] = gpo_finding.as_dict()
    # Keep inactive SPN accounts in Kerberos inventory/evidence, but do not
    # present them as active exposure findings in the operator overview.
    active_kerberos_findings = [x for x in kerberos_findings
                                if not (x.get("rule") == "Kerberoastable-account"
                                        and x.get("evidence", {}).get("enabled") is False)]
    all_findings = (finding_records + policy_findings + description_findings + active_kerberos_findings +
                    delegation_findings + relay_findings + smb_findings + acl_findings +
                    [x["normalized"] for x in gpo_findings])
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
    # Keep a non-destructive historical copy for this scan ID.
    workspace.write_json(workspace.history_root / "scan.json", {"domain": root, "target": target,
                                                                  "scan_id": workspace.scan_id})
    workspace.write_json(workspace.history_root / "coverage.json", coverage.as_dict())
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
    console.line()
    console.heading("Target")
    console.line(f"  Domain ............. {root}")
    console.line(f"  DC ................. {target}")
    console.line()
    console.heading("Collectors")
    console.status("  Native LDAP ........ PASS", "PASS")
    for module_id, label in (("bloodhound", "BloodHound"), ("adcs-certipy", "Certipy"),
                             ("ldapdomaindump", "LDAPDomainDump"), ("netexec", "NetExec")):
        result = external_results.get(module_id, {})
        state = result.get("status", "NOT CHECKED")
        display = {"PASS": "PASS", "FAILED": "FAILED", "UNAVAILABLE": "NOT AVAILABLE"}.get(state, state)
        console.status(f"  {label:<19} {display}", display)
    console.line()
    console.heading("Inventory")
    for key, label in (("users", "Users"), ("groups", "Groups"), ("computers", "Computers"),
                       ("domain_controllers", "Domain Controllers"), ("domains", "Domains"),
                       ("gmsa", "gMSAs")):
        console.line(f"  {label:<19} {inventory.counts().get(key, 0)}")
    console.line(f"  {'CAs':<19} {len(cas)}")
    console.line(f"  {'Templates':<19} {len(templates)}")
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
            console.line()
            console.heading(f"------------[ {category} ]------------")
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
                    if evidence.get("type"): console.line(f"    Type ............. {evidence['type']}")
                elif item.get("status") not in {"single-source", "corroborated"}:
                    console.line(f"    Status ........... {item.get('status', '').upper()}")
    console.line()
    console.heading("Workspace")
    console.line(console.paint(f"  {workspace.domain}/", "dim"))
    if collector.kerberos_session:
        collector.kerberos_session.close()
    return 0
