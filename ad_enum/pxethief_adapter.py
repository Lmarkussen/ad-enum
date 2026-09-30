"""PXEThief-backed SCCM/PXE exposure validation.

PXEThief owns the PXE wire protocol, media-variable handling, TFTP transfer,
and policy decryption.  AD-Enum only discovers candidate distribution points,
invokes the pinned PXEThief PR #11 checkout in its own isolated environment,
captures the raw artifacts, and normalizes the operator-facing state.

The public ``run_pxethief`` result is a bounded dictionary; raw stdout/stderr
stay in module artifacts and are never rendered in the console report.
"""
from __future__ import annotations

import os
import json
import re
import subprocess
from pathlib import Path

from .sccm_models import normalize_pxe_validation

# Exact pinned source required for the intended SCCM/PXE environment.  The
# default branch is known not to work for these targets and is never selected.
SOURCE_URL = "https://github.com/MWR-CyberSec/PXEThief.git"
PR_REFSPEC = "pull/11/head:pr-11"
PINNED_BRANCH = "pr-11"

# PXEThief reads ``settings.ini`` from its working directory.  AD-Enum supplies
# an explicit file so behavior does not depend on the operator's checkout.
SETTINGS_TEMPLATE = """[SCAPY SETTINGS]
automatic_interface_selection_mode = 1
manual_interface_selection_by_id =

[HTTP CONNECTION SETTINGS]
use_proxy = 0
use_tls = 0

[GENERAL SETTINGS]
sccm_base_url =
auto_exploit_blank_password = 1
"""

_BLANK_PASSWORD = "[!] Blank password on PXE boot found!"
_CONFIGURED_PASSWORD = "User configured password detected for task sequence media"
_NO_RESPONSE = "No DHCP responses recieved from MECM server"
_NO_ROUTE = "No route found to target host"
_NO_OPTION = "No variable file location (DHCP option 243) found"
_INTERFACE_RE = re.compile(r"\[\+\] Using interface:\s*(\S+)")
_MEDIA_RE = re.compile(r"\[!\] Variables File Location:\s*(.+)")
_BCD_RE = re.compile(r"\[!\] BCD File Location:\s*(.+)")
_NAA_USER_RE = re.compile(r"\[!\] Network Access Account Username:\s*'(.*)'")
_NAA_PASS_RE = re.compile(r"\[!\] Network Access Account Password:\s*'(.*)'")
_STEP_RE = re.compile(r'In TS Step "([^"]*)"')
_CRED_LINE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_]*)\s*-\s*(\S.*?)\s*$")
_CRED_NAME_HINTS = ("password", "account", "username", "user")


def _repo_root(explicit=None):
    return Path(explicit) if explicit else Path(__file__).resolve().parents[1]


def pxethief_root(repo_root=None):
    """Return the isolated PXEThief checkout path (env override honored)."""
    configured = os.environ.get("PXETHIEF_ROOT")
    if configured:
        return Path(configured)
    return _repo_root(repo_root) / ".cache" / "PXEThief"


def pxethief_python(checkout=None):
    base = Path(checkout) if checkout else pxethief_root()
    candidate = base / ".venv" / "bin" / "python3"
    return candidate if candidate.is_file() else None


def pxethief_script(checkout=None):
    base = Path(checkout) if checkout else pxethief_root()
    candidate = base / "pxethief.py"
    return candidate if candidate.is_file() else None


def pxethief_available(checkout=None):
    return bool(pxethief_python(checkout) and pxethief_script(checkout))


def _git(root, *args, timeout=10):
    try:
        result = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                                text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip() if not result.returncode else ""


def _checkout_commit(root):
    return _git(root, "rev-parse", "HEAD")


def _checkout_pinned(root):
    head = _checkout_commit(root)
    return bool(head) and head == _git(root, "rev-parse", PINNED_BRANCH)


def pxethief_capability(root=None):
    """Credential-free installation check used by doctor; never sends traffic."""
    root_path = pxethief_root(root)
    if not (root_path / ".git").exists():
        return {"status": "NOT AVAILABLE", "detail": f"{root_path} checkout not found",
                "root": str(root_path), "commit": ""}
    interpreter = pxethief_python(root_path)
    if not interpreter:
        return {"status": "NOT AVAILABLE", "detail": f"{root_path}/.venv/bin/python3 not found",
                "root": str(root_path), "commit": _checkout_commit(root_path)}
    if not pxethief_script(root_path):
        return {"status": "FAILED", "detail": f"{root_path}/pxethief.py not found",
                "root": str(root_path), "commit": _checkout_commit(root_path)}
    if not _checkout_pinned(root_path):
        return {"status": "FAILED",
                "detail": f"checkout is not on {PINNED_BRANCH} (required PR #11)",
                "root": str(root_path), "commit": _checkout_commit(root_path)}
    try:
        smoke = subprocess.run([str(interpreter), "-c",
                                "import scapy, tftpy, lxml, requests, Crypto, certipy"],
                               capture_output=True, text=True, timeout=60, check=False,
                               cwd=str(root_path))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "FAILED", "detail": f"{type(exc).__name__}: {exc}",
                "root": str(root_path), "commit": _checkout_commit(root_path)}
    if smoke.returncode:
        tail = (smoke.stderr or smoke.stdout).strip().splitlines()
        return {"status": "FAILED", "detail": tail[-1] if tail else "import check failed",
                "root": str(root_path), "commit": _checkout_commit(root_path)}
    commit = _checkout_commit(root_path)
    return {"status": "PASS", "detail": f"{root_path} (PR #11 @ {commit[:12]})",
            "root": str(root_path), "commit": commit}


def write_settings(path):
    """Write the explicit PXEThief ``settings.ini`` used for every invocation."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SETTINGS_TEMPLATE, encoding="utf-8")
    return path


def parse_pxethief_output(text):
    """Map PXEThief PR #11 stdout to a bounded, deterministic result."""
    output = str(text or "")
    result = {"state": "NOT TESTED", "interface": "", "media_file": "", "bcd_file": "",
              "network_access_accounts": [], "task_sequence_credentials": [],
              "evidence": [], "errors": []}
    interface = _INTERFACE_RE.search(output)
    if interface:
        result["interface"] = interface.group(1)
    media = _MEDIA_RE.search(output)
    if media:
        result["media_file"] = media.group(1).strip()
    bcd = _BCD_RE.search(output)
    if bcd:
        result["bcd_file"] = bcd.group(1).strip()
    users = _NAA_USER_RE.findall(output)
    passwords = _NAA_PASS_RE.findall(output)
    for username, password in zip(users, passwords):
        result["network_access_accounts"].append(
            {"name": "NetworkAccessAccount", "username": username, "value": password})
    step = ""
    for line in output.splitlines():
        step_match = _STEP_RE.search(line)
        if step_match:
            step = step_match.group(1)
            continue
        cred_match = _CRED_LINE_RE.match(line)
        if not cred_match:
            continue
        name, value = cred_match.group(1), cred_match.group(2)
        if any(hint in name.casefold() for hint in _CRED_NAME_HINTS):
            result["task_sequence_credentials"].append(
                {"name": name, "value": value, "step": step})
    # Deduplicate while preserving order; PXEThief repeats policies per target.
    for key in ("network_access_accounts", "task_sequence_credentials"):
        seen, unique = set(), []
        for item in result[key]:
            fingerprint = (item.get("name"), item.get("username"), item.get("value"))
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            unique.append(item)
        result[key] = unique
    if _BLANK_PASSWORD in output:
        result["state"] = "VULNERABLE"
        result["evidence"].append("PXE boot media accepted the blank/derived media password")
    elif _CONFIGURED_PASSWORD in output:
        result["state"] = "NOT VULNERABLE"
        result["evidence"].append("PXE media is protected by a configured password")
    elif _NO_RESPONSE in output or _NO_ROUTE in output or _NO_OPTION in output:
        result["state"] = "NOT TESTED"
        reason = (_NO_RESPONSE if _NO_RESPONSE in output else
                  _NO_ROUTE if _NO_ROUTE in output else _NO_OPTION)
        result["errors"].append(reason)
    elif "PermissionError" in output or "Operation not permitted" in output:
        result["state"] = "NOT TESTED"
        result["errors"].append("packet capture requires root or CAP_NET_RAW/CAP_NET_ADMIN")
    else:
        result["errors"].append("PXEThief produced no recognized PXE state marker")
    return result


def run_pxethief(target, *, timeout=120, workdir, root=None):
    """Run exactly one PXEThief PR #11 assessment against a known DP."""
    root_path = pxethief_root(root)
    interpreter = pxethief_python(root_path)
    script = pxethief_script(root_path)
    workdir = Path(workdir)
    if not interpreter or not script:
        return normalize_pxe_validation({"dp": str(target), "state": "NOT TESTED",
                                         "errors": ["PXEThief unavailable"], "source": ""})
    write_settings(workdir / "settings.ini")
    command = [str(interpreter), str(script), "2", str(target)]
    try:
        completed = subprocess.run(command, cwd=str(workdir), capture_output=True,
                                   text=True, timeout=float(timeout), check=False)
        stdout, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired:
        return normalize_pxe_validation({"dp": str(target), "state": "NOT TESTED",
                                         "source": "PXEThief",
                                         "errors": [f"PXEThief timed out after {timeout}s"]})
    except OSError as exc:
        return normalize_pxe_validation({"dp": str(target), "state": "NOT TESTED",
                                         "source": "PXEThief",
                                         "errors": [f"{type(exc).__name__}: {exc}"]})
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "stdout.txt").write_text(stdout or "", encoding="utf-8", errors="replace")
    (workdir / "stderr.txt").write_text(stderr or "", encoding="utf-8", errors="replace")
    parsed = parse_pxethief_output(stdout + "\n" + stderr)
    recovered = (parsed["network_access_accounts"] + parsed["task_sequence_credentials"])
    parsed.update({"dp": str(target), "returncode": returncode,
                   "recovered": recovered, "sources": ["PXEThief"], "source": "PXEThief",
                   "command": f"pxethief.py 2 {target}"})
    if returncode and not recovered:
        parsed["errors"].append(f"PXEThief exit {returncode}")
    normalized = normalize_pxe_validation(parsed)
    try:
        (workdir / "run.json").write_text(
            json.dumps({"dp": str(target), "command": parsed.get("command", ""),
                        "returncode": returncode, "state": normalized["state"],
                        "interface": normalized["interface"],
                        "recovered_count": normalized["recovered_count"]},
                       indent=2, sort_keys=True), encoding="utf-8")
    except OSError:
        pass
    return normalized
