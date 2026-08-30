"""Bounded adapter for the supported CinderPath CRED-1 implementation."""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .sccm_models import normalize_cred1_evidence


def cinderpath_path():
    candidates = []
    configured = os.environ.get("CINDERPATH_BIN")
    if configured:
        candidates.append(configured)
    candidates.extend((shutil.which("cinderpath"),
                       str(Path.home() / ".local/bin/cinderpath"),
                       str(Path.cwd() / ".venv/bin/cinderpath"),
                       str(Path(__file__).resolve().parent.parent / ".venv/bin/cinderpath")))
    return next((x for x in candidates if x and Path(x).is_file()), None)


def cinderpath_capability(executable=None):
    executable = executable or cinderpath_path()
    if not executable:
        return {"status": "NOT TESTED", "reason": "CinderPath unavailable"}
    try:
        result = subprocess.run([executable, "assess", "CRED-1", "--help"],
                                capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "TOOL FAILURE", "reason": f"{type(exc).__name__}: {exc}"}
    text = (result.stdout or "") + (result.stderr or "")
    if result.returncode or "--format" not in text:
        return {"status": "NOT TESTED", "reason": "CinderPath lacks required structured CRED-1 output"}
    return {"status": "READY", "version_help": text[:2000]}


def _secrets(payload):
    values = payload.get("recovered_secrets", []) or []
    result, seen = [], set()
    for item in values:
        if not isinstance(item, dict):
            continue
        value = item.get("value", item.get("password", ""))
        name = item.get("name", "")
        username = item.get("username", "")
        key = (str(name).lower(), str(username).lower(), str(value))
        if not value or key in seen:
            continue
        seen.add(key)
        result.append({"name": name, "type": item.get("type", "task_sequence_variable"),
                       "username": username, "value": value,
                       "source_policy": item.get("source_policy", item.get("policy_id", "")),
                       "task_sequence": item.get("task_sequence", item.get("package_id", "")),
                       "sources": list(item.get("sources", []) or [])})
    return result


def run_cinderpath_cred1(target, *, timeout=60, executable=None):
    """Invoke exactly one live CinderPath CRED-1 assessment.

    The isolated output directory is temporary so CinderPath's operational
    database/report state cannot become an AD-Enum artifact. No credentials
    are passed to this command.
    """
    executable = executable or cinderpath_path()
    if not executable:
        return normalize_cred1_evidence({"dp": target, "status": "NOT TESTED",
                                         "errors": ["CinderPath unavailable"],
                                         "sources": ["CinderPath"]})
    capability = cinderpath_capability(executable)
    if capability["status"] != "READY":
        return normalize_cred1_evidence({"dp": target, "status": capability["status"],
                                         "errors": [capability["reason"]],
                                         "sources": ["CinderPath"]})
    with tempfile.TemporaryDirectory(prefix="ad-enum-cinderpath-") as temp:
        root = Path(temp)
        command = [executable, "assess", "CRED-1", "--target", str(target),
                   "--format", "json", "--no-color", "--db", str(root / "run.db"),
                   "--output-dir", str(root / "reports"), "--log-level", "error"]
        try:
            completed = subprocess.run(command, cwd=root, capture_output=True, text=True,
                                       timeout=float(timeout), check=False)
        except subprocess.TimeoutExpired as exc:
            return normalize_cred1_evidence({"dp": target, "status": "TIMEOUT",
                                             "errors": [f"CinderPath timed out after {timeout}s"],
                                             "sources": ["CinderPath"]})
        except OSError as exc:
            return normalize_cred1_evidence({"dp": target, "status": "TOOL FAILURE",
                                             "errors": [f"{type(exc).__name__}: {exc}"],
                                             "sources": ["CinderPath"]})
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        return normalize_cred1_evidence({"dp": target, "status": "FAILED",
                                         "errors": ["CinderPath returned malformed JSON"],
                                         "sources": ["CinderPath"]})
    payload["dp"] = payload.get("dp", target)
    payload["site_code"] = payload.get("site", payload.get("site_code", ""))
    payload["interface"] = payload.get("interface", "")
    payload["credentials"] = _secrets(payload)
    completed_ok = str(payload.get("status", "")).lower() in {"completed", "complete", "confirmed"}
    payload["status"] = "CONFIRMED" if payload["credentials"] else ("COMPLETE" if completed_ok else payload.get("status", "FAILED"))
    if completed_ok:
        payload.setdefault("pxe", "CONFIRMED")
        payload.setdefault("wds", "CONFIRMED")
        payload.setdefault("tftp", "CONFIRMED")
        payload.setdefault("boot_var", "RECOVERED")
        payload.setdefault("media_identity", "RECOVERED")
        payload.setdefault("assignment", "RECEIVED")
        payload.setdefault("certificate", "USABLE")
        payload.setdefault("secret_inspection", "COMPLETE")
    payload["policies"] = payload.get("task_sequence_policies", payload.get("policy_count", 0))
    payload["sources"] = list(payload.get("sources", []) or []) + ["CinderPath"]
    if completed.returncode:
        payload.setdefault("errors", []).append(f"CinderPath exit {completed.returncode}")
    return normalize_cred1_evidence(payload)
