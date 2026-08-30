"""Ordered, failure-isolated execution of external read-only collectors."""
from .adapters.bloodhound import BloodHoundAdapter
from .adapters.certipy import CertipyAdapter
from .adapters.ldapdomaindump import LDAPDomainDumpAdapter
from .adapters.netexec import NetExecAdapter
from .adapters.networkhound import NetworkHoundAdapter
from .adapters.relayking import RelayKingAdapter
from .inventory import native_inventory

ADAPTERS = {
    "bloodhound": BloodHoundAdapter,
    "adcs-certipy": CertipyAdapter,
    "ldapdomaindump": LDAPDomainDumpAdapter,
    "netexec": NetExecAdapter,
    "relay": RelayKingAdapter,
    "networkhound": NetworkHoundAdapter,
}

def execute_external(context, plan, *, certipy_snapshot=None, progress=None):
    results, diagnostics = {}, []
    for item in plan:
        adapter_type = ADAPTERS.get(item.spec.id)
        if adapter_type is None or item.spec.id in {"ldap", "adcs-native"}: continue
        if progress: progress("start", item.spec.name)
        if item.status.value != "READY":
            results[item.spec.id] = {"status": item.status.value, "reason": item.reason}
            if progress: progress("end", item.spec.name, item.status.value)
            continue
        try:
            if item.spec.id == "adcs-certipy" and certipy_snapshot is not None:
                results[item.spec.id] = {"status": "PASS", "snapshot": certipy_snapshot}
            elif item.spec.id == "adcs-certipy":
                results[item.spec.id] = {"status": "PASS", "snapshot": adapter_type().run(
                    domain=context.domain, username=context.auth.username, password=context.auth.password,
                    dc_ip=context.dc_ip, workspace=context.workspace, timeout=context.timeout,
                    ldaps=context.ldaps, force_kerb=context.force_kerb)}
            else:
                results[item.spec.id] = {"status": "PASS", "result": adapter_type().run(context=context)}
            if progress: progress("end", item.spec.name, "PASS")
        except Exception as exc:
            results[item.spec.id] = {"status": "FAILED", "reason": f"{type(exc).__name__}: {exc}"}
            diagnostics.append(f"{item.spec.id}: {type(exc).__name__}: {exc}")
            context.workspace.write_json(context.workspace.raw_dir(item.spec.outputs[0]) / "failure.json",
                                         results[item.spec.id])
            if progress: progress("end", item.spec.name, "FAILED")
    return results, diagnostics
