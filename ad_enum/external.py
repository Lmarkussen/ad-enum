"""Ordered, failure-isolated execution of external read-only collectors."""
import re

from .adapters.certipy import CertipyAdapter
from .adapters.ldapdomaindump import LDAPDomainDumpAdapter
from .adapters.netexec import NetExecAdapter
from .adapters.networkhound import NetworkHoundAdapter
from .adapters.relayking import RelayKingAdapter
from .inventory import native_inventory

ADAPTERS = {
    "adcs-certipy": CertipyAdapter,
    "ldapdomaindump": LDAPDomainDumpAdapter,
    "netexec": NetExecAdapter,
    "relay": RelayKingAdapter,
    "networkhound": NetworkHoundAdapter,
}


def failure_summary(exc):
    """Return a concise, non-secret operator-facing failure reason.

    The exception text has already been redacted by the adapter, so no scanner
    secret can end up in the summary.
    """
    text = str(exc)
    lowered = text.casefold()
    if "strongerauthrequired" in lowered or "stronger_auth_required" in lowered \
            or "stronger authentication" in lowered:
        return "DC requires protected LDAP"
    if any(token in lowered for token in ("certificate verify", "sslerror", "ssl error",
                                          "tls handshake", "tls", "ssl")):
        return "TLS connection failed"
    hash_match = re.search(r"unsupported hash type\s+(\w+)", text, re.IGNORECASE)
    if hash_match:
        return f"dependency error: {hash_match.group(1).upper()} unavailable"
    if any(token in lowered for token in ("modulenotfounderror", "no module named", "importerror")):
        return "dependency error: missing Python module"
    if any(token in lowered for token in ("invalidcredentials", "invalid credentials",
                                          "logon failure", "0x52e", "authentication failed",
                                          "authentication rejected")):
        return "authentication rejected"
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    first = re.sub(r"^(RuntimeError|FileNotFoundError|OSError|TimeoutError):\s*", "", first)
    first = re.sub(r"^[\w.-]+ exited \d+:\s*", "", first)
    return first[:120] or "execution error"

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
            previous_callback = getattr(context, "tool_output_callback", None)
            if context.tool_output:
                context.tool_output_callback = lambda stream, line, label=item.spec.name: progress("tool", label, stream, line) if progress else None
            if item.spec.id == "adcs-certipy" and certipy_snapshot is not None:
                results[item.spec.id] = {"status": "PASS", "snapshot": certipy_snapshot}
            elif item.spec.id == "adcs-certipy":
                results[item.spec.id] = {"status": "PASS", "snapshot": adapter_type().run(
                    domain=context.domain, username=context.auth.username, password=context.auth.password,
                    dc_ip=context.dc_ip, workspace=context.workspace, timeout=context.timeout,
                    ldaps=context.ldaps, force_kerb=context.force_kerb,
                    stream=context.tool_output_callback)}
            else:
                results[item.spec.id] = {"status": "PASS", "result": adapter_type().run(context=context)}
            if progress: progress("end", item.spec.name, "PASS")
        except Exception as exc:
            summary = failure_summary(exc)
            results[item.spec.id] = {"status": "FAILED", "summary": summary,
                                     "reason": f"{type(exc).__name__}: {exc}"}
            diagnostics.append(f"{item.spec.id}: {type(exc).__name__}: {exc}")
            context.workspace.write_json(context.workspace.raw_dir(item.spec.outputs[0]) / "failure.json",
                                         results[item.spec.id])
            if progress: progress("end", item.spec.name, "FAILED", summary)
        finally:
            context.tool_output_callback = previous_callback if 'previous_callback' in locals() else None
    return results, diagnostics
