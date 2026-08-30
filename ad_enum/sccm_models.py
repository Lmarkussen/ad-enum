"""Offline-safe SCCM metadata models and bounded artifact policy."""
from dataclasses import dataclass


@dataclass(frozen=True)
class SCCMArtifactLimits:
    max_files: int = 32
    max_file_bytes: int = 262144
    max_total_bytes: int = 1048576


def normalize_pxe_evidence(data):
    data = data if isinstance(data, dict) else {}
    return {"state": str(data.get("state", data.get("status", "NOT TESTED"))).upper(),
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


def bounded_artifact_candidates(items, limits=None):
    limits = limits or SCCMArtifactLimits()
    selected, total = [], 0
    for item in items or []:
        if len(selected) >= limits.max_files: break
        size = int(item.get("size", 0) or 0)
        if size < 0 or size > limits.max_file_bytes or total + size > limits.max_total_bytes: continue
        selected.append(item); total += size
    return selected
