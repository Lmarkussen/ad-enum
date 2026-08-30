"""Offline-safe SCCM metadata models and bounded artifact policy.

These helpers deliberately normalize observations; they do not turn
administrator-known lab facts into scanner findings.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class SCCMArtifactLimits:
    max_files: int = 32
    max_file_bytes: int = 262144
    max_total_bytes: int = 1048576


def normalize_pxe_evidence(data):
    data = data if isinstance(data, dict) else {}
    state = str(data.get("state", data.get("status", "NOT TESTED"))).upper()
    return {"state": state, "status": state,
            "host": data.get("host", ""), "dp": data.get("dp", ""),
            "implementation": data.get("implementation", "UNKNOWN"),
            "wds": data.get("wds", "UNKNOWN"), "tftp": data.get("tftp", "UNKNOWN"),
            "architectures": list(data.get("architectures", []) or []),
            "boot_filenames": list(data.get("boot_filenames", []) or []),
            "boot_metadata": data.get("boot_metadata", "UNKNOWN"),
            "protection": data.get("protection", "UNKNOWN"),
            "sources": list(data.get("sources", []) or []),
            "evidence": list(data.get("evidence", []) or [])}


def normalize_sql_relationship(data):
    data = data if isinstance(data, dict) else {}
    return {"site_code": data.get("site_code", ""), "host": data.get("host", ""),
            "instance": data.get("instance", ""), "database": data.get("database", ""),
            "status": data.get("status", "NOT TESTED"), "confidence": data.get("confidence", "UNKNOWN"),
            "sources": list(data.get("sources", []) or []), "evidence": list(data.get("evidence", []) or [])}


def normalize_mp_metadata(data):
    """Normalize bounded client-visible Management Point metadata."""
    data = data if isinstance(data, dict) else {}
    return {
        "host": data.get("host", data.get("fqdn", "")),
        "fqdn": data.get("fqdn", data.get("host", "")),
        "site_code": data.get("site_code", data.get("sitecode", "")),
        "protocol": str(data.get("protocol", "UNKNOWN")).upper(),
        "port": data.get("port"),
        "version": data.get("version", data.get("build", "")),
        "ssl_state": data.get("ssl_state", data.get("SSLState", "UNKNOWN")),
        "authentication": data.get("authentication", "UNKNOWN"),
        "capabilities": sorted({str(x) for x in (data.get("capabilities", []) or [])}),
        "sources": list(data.get("sources", []) or []),
        "evidence": list(data.get("evidence", []) or []),
        "status": str(data.get("status", "NOT TESTED")).upper(),
    }


def normalize_dp_content(items, limits=None):
    """Normalize bounded DP content metadata without fetching content."""
    result = []
    for item in bounded_artifact_candidates(items or [], limits):
        if not isinstance(item, dict):
            continue
        result.append({
            "package_id": item.get("package_id", item.get("package", "")),
            "content_id": item.get("content_id", item.get("content", "")),
            "name": item.get("name", item.get("package_name", "")),
            "boot_image": item.get("boot_image", ""),
            "task_sequence": item.get("task_sequence", ""),
            "size": int(item.get("size", 0) or 0),
            "url": item.get("url", item.get("path", "")),
            "source": item.get("source", ""),
            "access": str(item.get("access", "UNKNOWN")).upper(),
        })
    return result


def normalize_task_sequences(items):
    """Keep task-sequence metadata, never execution material or secrets."""
    result = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        result.append({
            "id": item.get("id", item.get("task_sequence_id", "")),
            "name": item.get("name", ""),
            "package_references": list(item.get("package_references", []) or []),
            "boot_image": item.get("boot_image", ""),
            "referenced_hosts": list(item.get("referenced_hosts", []) or []),
            "variables": list(item.get("variables", []) or []),
            "source": item.get("source", ""),
            "access": str(item.get("access", "UNKNOWN")).upper(),
        })
    return result


def normalize_sccm_topology(data):
    """Normalize topology nodes/relationships with explicit confidence."""
    data = data if isinstance(data, dict) else {}
    nodes = []
    for node in data.get("nodes", []) or []:
        if not isinstance(node, dict):
            continue
        nodes.append({
            "host": node.get("host", ""), "ip": node.get("ip", ""),
            "role": node.get("role", ""), "site": node.get("site", node.get("site_code", "")),
            "status": str(node.get("status", "UNKNOWN")).upper(),
            "confidence": str(node.get("confidence", "UNKNOWN")).upper(),
            "low_priv_visibility": str(node.get("low_priv_visibility", "UNKNOWN")).upper(),
            "sources": list(node.get("sources", []) or []),
            "evidence": list(node.get("evidence", []) or []),
        })
    relationships = []
    for rel in data.get("relationships", []) or []:
        if not isinstance(rel, dict):
            continue
        relationships.append({
            "from": rel.get("from", ""), "to": rel.get("to", ""),
            "role": rel.get("role", ""), "site": rel.get("site", rel.get("site_code", "")),
            "status": str(rel.get("status", "UNKNOWN")).upper(),
            "confidence": str(rel.get("confidence", "UNKNOWN")).upper(),
            "sources": list(rel.get("sources", []) or []),
            "evidence": list(rel.get("evidence", []) or []),
        })
    return {"site_code": data.get("site_code", ""), "nodes": nodes,
            "relationships": relationships, "sources": list(data.get("sources", []) or [])}


def normalize_sccm_capabilities(data):
    """Normalize per-capability SCCM coverage; aggregate PASS is avoided."""
    data = data if isinstance(data, dict) else {}
    allowed = {"COMPLETE", "PARTIAL", "NOT OBSERVABLE", "NOT CONFIGURED", "NOT TESTED", "FAILED"}
    result = {}
    for name, value in data.items():
        if isinstance(value, dict):
            status = str(value.get("status", "NOT TESTED")).upper()
            detail = value.get("detail", "")
        else:
            status, detail = str(value).upper(), ""
        result[str(name)] = {"status": status if status in allowed else "UNKNOWN", "detail": detail}
    return result


def normalize_cred1_evidence(data):
    """Normalize safe CRED-1 evidence without decrypting protected media."""
    data = data if isinstance(data, dict) else {}
    return {
        "dp": data.get("dp", data.get("host", "")),
        "status": str(data.get("status", "PARTIAL")).upper(),
        "site_code": data.get("site_code", data.get("site", "")),
        "interface": data.get("interface", ""),
        "pxe": str(data.get("pxe", "UNKNOWN")).upper(),
        "wds": str(data.get("wds", "UNKNOWN")).upper(),
        "tftp": str(data.get("tftp", "UNKNOWN")).upper(),
        "boot_file": data.get("boot_file", data.get("BootFileName", "")),
        "artifacts": list(data.get("artifacts", []) or []),
        "media_protection": str(data.get("media_protection", "UNKNOWN")).upper(),
        "secret_exposure": str(data.get("secret_exposure", "UNKNOWN")).upper(),
        "secret_inspection": data.get("secret_inspection", "NOT ATTEMPTED"),
        "credentials": list(data.get("credentials", data.get("recovered_secrets", [])) or []),
        "stages": data.get("stages", {}),
        "policies": data.get("policies", data.get("task_sequence_policies", 0)),
        "errors": list(data.get("errors", []) or []),
        "sources": list(data.get("sources", []) or []),
        "evidence": list(data.get("evidence", []) or []),
    }


def sccm_technique_coverage():
    """Engineering matrix; model presence is not treated as implementation."""
    return {
        "RECON-1": "PARTIAL", "RECON-2": "PARTIAL", "RECON-3": "PARTIAL",
        "RECON-4": "PARTIAL", "RECON-5": "PARTIAL", "RECON-6": "PARTIAL",
        "RECON-7": "PARTIAL", "CRED-1": "PARTIAL",
    }


def bounded_artifact_candidates(items, limits=None):
    limits = limits or SCCMArtifactLimits()
    selected, total = [], 0
    for item in items or []:
        if len(selected) >= limits.max_files: break
        size = int(item.get("size", 0) or 0)
        if size < 0 or size > limits.max_file_bytes or total + size > limits.max_total_bytes: continue
        selected.append(item); total += size
    return selected
