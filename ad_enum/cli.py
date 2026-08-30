import argparse
import sys
import ipaddress
import shutil
from .ldap_collect import Collector
from .adcs import scan
from .adapters.certipy import CertipyAdapter
from .core.workspace import ScanWorkspace, canonical_domain
from .core.autoconfig import inspect as inspect_autoconfig
from .core.context import AuthContext, ScanContext
from .core.planner import ExecutionPlanner
from .core.findings import NormalizedFinding
from .external import execute_external
from .inventory import native_inventory, DomainInventory, build_targets, sensitive_description, parse_netexec_smb
from .sccm import discover as discover_sccm
from .kerberos import roastable
from .delegation import enumerate_delegation, enumerate_gmsa


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
    p.add_argument("--auto-config", action="store_true"); p.add_argument("--verbose", "--debug", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--timeout", type=float, default=10)
    p.add_argument("--modules", default="all", help="comma-separated modules (default: all read-only collectors)")
    p.add_argument("--profile", default="default")
    p.add_argument("--certipy-json", help="optional Certipy -json result for corroboration")
    p.add_argument("--output-dir", default="./tool")
    a = p.parse_args(argv)
    if a.password is None:
        import getpass; a.password = getpass.getpass("LDAP password: ")
    target = a.dc or a.domain
    try:
        ipaddress.ip_address(a.domain)
        bind_domain = ""
    except ValueError:
        bind_domain = a.domain
    green, red, reset = ("", "", "") if a.no_color else ("\033[32m", "\033[31m", "\033[0m")
    collector = Collector(target, a.username, a.password, bind_domain, a.ldaps, a.port,
                          timeout=a.timeout, force_kerb=a.force_kerb)
    try:
        root, _ = collector.preflight()
    except Exception as exc:
        print(f"{red}Credentials Invalid{reset}")
        if a.verbose: print(f"[DEBUG] preflight failed: {type(exc).__name__}: {exc}")
        return 2
    if not ipaddress.ip_address(a.domain) if False else False:
        pass
    try:
        ipaddress.ip_address(a.domain)
        supplied_is_ip = True
    except ValueError:
        supplied_is_ip = False
    if not supplied_is_ip and canonical_domain(a.domain) != canonical_domain(root):
        print(f"Domain mismatch: supplied {a.domain}, discovered {root}")
        return 2
    print(f"{green}Credentials are Valid{reset}")
    workspace = ScanWorkspace(a.output_dir, root, original_target=target)
    print(f"Domain: {root}")
    requested = []
    for module in (x.strip().lower() for x in a.modules.split(",") if x.strip()):
        if module == "all": requested.extend(("bloodhound", "adcs-certipy", "ldapdomaindump", "netexec", "ldap", "adcs-native", "kerberos", "delegation", "sccm-discovery"))
        elif module == "adcs": requested.extend(("ldap", "adcs-native", "adcs-certipy"))
        else: requested.append(module)
    plan = ExecutionPlanner().plan(requested or ["adcs-native"])
    if a.verbose:
        print("Execution plan")
        for item in plan: print(f"  {item.spec.name} ........ {item.status.value}{(' - ' + item.reason) if item.reason else ''}")
    imported_certipy = CertipyAdapter().from_json(a.certipy_json) if a.certipy_json else None
    context = ScanContext(workspace.domain, target, AuthContext(a.username, a.password, bind_domain),
                          workspace, timeout=a.timeout, scan_id=workspace.scan_id,
                          ldaps=a.ldaps, force_kerb=a.force_kerb,
                          auto_config={"requested": a.auto_config})
    if a.auto_config:
        context.auto_config = inspect_autoconfig(a.dc or target, workspace.domain)
        context.dc_hostname = context.auto_config.get("dc_hostname", "")
        if a.verbose: print(f"Auto-config: {context.auto_config}")
    # Native LDAP is the discovery prerequisite for the multi-host plan.
    root, cas, templates = collector.collect()
    inventory = native_inventory(collector.raw)
    native_counts = inventory.counts()
    context.targets = build_targets(inventory)
    external_results, external_diagnostics = execute_external(context, plan, certipy_snapshot=imported_certipy)
    certipy_result = external_results.get("adcs-certipy", {}).get("snapshot") if external_results.get("adcs-certipy", {}).get("status") == "PASS" else None
    certipy = certipy_result or imported_certipy
    print(f"CAs: {len(cas)}\nTemplates: {len(templates)}")
    source_counts = {"native-ldap": native_counts}
    for result in external_results.values():
        obj = result.get("result", {}) if isinstance(result, dict) else {}
        if hasattr(obj.get("inventory") if isinstance(obj, dict) else None, "records"):
            inventory.merge(obj["inventory"])
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
        if a.verbose or status == "PASS":
            result_obj = result.get("result", {})
            inv = result_obj.get("inventory") if isinstance(result_obj, dict) else None
            if hasattr(inv, "counts"):
                counts = inv.counts()
                source_counts[result_obj.get("source", module_id)] = counts
                print(f"[*] {labels.get(module_id, module_id)}: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
            elif status == "PASS":
                print(f"[*] {labels.get(module_id, module_id)}: collected")
    print("[*] Native LDAP: " + ", ".join(f"{k}={v}" for k, v in native_counts.items()))
    ldd_result = external_results.get("ldapdomaindump", {}).get("result", {})
    ldd_inv = ldd_result.get("inventory") if isinstance(ldd_result, dict) else None
    if hasattr(ldd_inv, "records"):
        native_users = inventory.records.get("users", {})
        ldd_users = ldd_inv.records.get("users", {})
        descriptions = sum(bool(r.attributes.get("description")) for r in ldd_users.values())
        print(f"[*] LDAPDomainDump users with descriptions: {descriptions}")
    for module_id, result in external_results.items():
        result_obj = result.get("result", {}) if isinstance(result, dict) else {}
        if result_obj.get("password_policy"):
            inventory.password_policy = result_obj["password_policy"]
        if result_obj.get("hosts"):
            for host in result_obj["hosts"]:
                inventory.add("observed_hosts", f"{host.get('ip')}:{host.get('host', host.get('name', ''))}", host, "netexec")
    sccm_result = discover_sccm(inventory)
    workspace.write_json(workspace.findings_path("SCCM", "inventory.json"), sccm_result)
    coverage.add("SCCM / infrastructure discovery", "PASS", f"{len(sccm_result['hosts'])} candidate host(s)")
    coverage.add("Relay enumeration", "NOT RUN", "future RelayKing-Depth integration")
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
            rule="AS-REP-roastable", title=f"AS-REP roastable user ({state})",
            affected_object=item.username, domain=workspace.domain,
            sources=[{"source": source} for source in item.sources],
            evidence={"enabled": item.enabled, "preauthentication_required": False,
                      "userAccountControl": item.attributes.get("userAccountControl")},
            status="single-source", priority="medium", workspace_artifacts=["Kerberos/inventory.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    for item in exposures["kerberoast"]:
        state = "enabled" if item.enabled else "disabled"
        kerberos_findings.append(NormalizedFinding(
            finding_id=f"kerberos:spn:{item.identifier}", category="KERBEROS",
            rule="Kerberoastable-account", title=f"Kerberoastable account ({state})",
            affected_object=item.username, domain=workspace.domain,
            sources=[{"source": source} for source in item.sources],
            evidence={"enabled": item.enabled, "spns": item.spns,
                      "userAccountControl": item.attributes.get("userAccountControl"),
                      "pwdLastSet": item.attributes.get("pwdLastSet")},
            status="single-source", priority="medium", workspace_artifacts=["Kerberos/inventory.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    for item in exposures["password_not_required"]:
        kerberos_findings.append(NormalizedFinding(
            finding_id=f"account:passwd-not-required:{item.identifier}", category="ACCOUNT",
            rule="PASSWD_NOTREQD", title="Password not required", affected_object=item.username,
            domain=workspace.domain, sources=[{"source": source} for source in item.sources],
            evidence={"enabled": True, "userAccountControl": item.attributes.get("userAccountControl")},
            status="single-source", priority="medium", workspace_artifacts=["Kerberos/inventory.json"],
            first_seen_scan=workspace.scan_id, current_scan=workspace.scan_id).as_dict())
    delegation_findings = []
    for item in delegation_records:
        if item.kind == "unconstrained" and item.expected_dc: continue
        delegation_findings.append(NormalizedFinding(
            finding_id=f"delegation:{item.kind}:{item.target}", category="DELEGATION", rule=item.kind,
            title=f"{item.kind.replace('-', ' ').title()} delegation", affected_object=item.target,
            domain=workspace.domain, sources=[{"source": source} for source in item.sources],
            evidence=item.as_dict(), status="single-source", priority="medium",
            workspace_artifacts=["Delegation/inventory.json"], first_seen_scan=workspace.scan_id,
            current_scan=workspace.scan_id).as_dict())
    workspace.write_json(workspace.findings_path("LDAP", "findings.json"), policy_findings + description_findings)
    workspace.write_json(workspace.findings_path("Kerberos", "findings.json"), kerberos_findings)
    workspace.write_json(workspace.findings_path("Delegation", "findings.json"), delegation_findings)
    all_findings = finding_records + policy_findings + description_findings + kerberos_findings + delegation_findings
    workspace.write_json(workspace.findings_path("vulnerabilities", "findings.json"), all_findings)
    workspace.write_text(workspace.findings_path("vulnerabilities", "findings.txt"),
                          "\n".join(f"[{x['category']}] {x['title']}" for x in all_findings) + "\n")
    workspace.write_json(workspace.root / "external-results.json", external_results)
    published = set()
    for t, ca, native in findings:
            published.add(t.name)
            vulnerable, reasons = native.vulnerable, native.detail.split("; ") if native.detail else []
            if a.verbose:
                print(f"[DEBUG] template={t.name} flags=0x{t.name_flags:x}/0x{t.enrollment_flags:x} ekus={t.ekus} application_policies={t.application_policies}")
                for ace in t.security_descriptor or []: print(f"[DEBUG] ACE type={ace.ace_type} kind={ace.kind} sid={ace.sid} mask=0x{ace.mask:x} object_type={ace.object_type} inherited={ace.inherited}")
            if vulnerable:
                print(f"[ESC1] {t.display_name or t.name}\n  CA: {ca.name}\n  Enrollee supplies subject/SAN: yes\n  Reason: {reasons[-1]}")
            elif a.verbose:
                print(f"[DEBUG] template={t.name} CA={ca.name} result=NOT ESC1 rejected because: {'; '.join(reasons)}")
    if a.verbose:
        for t in templates:
            if t.name not in published:
                from .rules import classify_esc1
                from .models import PrincipalContext, CA
                principals = PrincipalContext(set().union(*(x.evidence.get("low_privileged_subject_sids", set()) for x in templates)))
                _, reasons = classify_esc1(t, CA("", ""), principals, False)
                print(f"[DEBUG] template={t.name} result=NOT ESC1 rejected because: {'; '.join(reasons)}")
        for ca, ref in dangling: print(f"[DEBUG] dangling publication: CA={ca} template={ref}")
        for key, values in duplicates.items(): print(f"[DEBUG] duplicate template key={key} count={len(values)}")
        print(coverage.render("Coverage"))
    if certipy:
        for name, comparison in comparisons.items():
            if len(comparison.assessments) > 1:
                print(f"[CORROBORATION] {name}: {comparison.status}")
                if comparison.status == "disagreement":
                    for assessment in comparison.assessments:
                        print(f"  {assessment.source}: {assessment.vulnerable} ({assessment.detail})")
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
    print(f"Workspace: {workspace.root}")
    return 0
