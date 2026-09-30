"""SCCMHunter discovery/profiling adapter (enumeration only).

SCCMHunter is used strictly as an independent LDAP discovery source that
corroborates and enriches AD-Enum's native SCCM topology.  Only the read-only
``find`` command is invoked; no exploitation or post-exploitation module is
ever scheduled.

``find`` writes its results to a SQLite database below ``~/.sccmhunter``.  The
adapter redirects ``HOME`` to a per-scan working directory so the database and
any loot stay inside the AD-Enum workspace instead of the operator's home.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
from pathlib import Path


SOURCE_URL = "https://github.com/garrettfoster13/sccmhunter.git"
COMMAND = "find"


def _repo_root(explicit=None):
    return Path(explicit) if explicit else Path(__file__).resolve().parents[1]


def sccmhunter_root(repo_root=None):
    """Return the isolated SCCMHunter checkout path (env override honored)."""
    configured = os.environ.get("SCCMHUNTER_ROOT")
    if configured:
        return Path(configured)
    return _repo_root(repo_root) / ".cache" / "SCCMHunter"


def sccmhunter_python(checkout=None):
    base = Path(checkout) if checkout else sccmhunter_root()
    candidate = base / ".venv" / "bin" / "python3"
    return candidate if candidate.is_file() else None


def sccmhunter_script(checkout=None):
    base = Path(checkout) if checkout else sccmhunter_root()
    candidate = base / "sccmhunter.py"
    return candidate if candidate.is_file() else None


def _git(root, *args, timeout=10):
    try:
        result = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                                text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip() if not result.returncode else ""


def _checkout_commit(root):
    return _git(root, "rev-parse", "HEAD")


def sccmhunter_capability(checkout=None):
    """Credential-free installation check used by doctor; never sends traffic."""
    root = sccmhunter_root(checkout)
    if not (root / ".git").exists():
        return {"status": "NOT AVAILABLE", "detail": f"{root} checkout not found",
                "root": str(root), "commit": ""}
    interpreter = sccmhunter_python(root)
    if not interpreter:
        return {"status": "NOT AVAILABLE", "detail": f"{root}/.venv/bin/python3 not found",
                "root": str(root), "commit": _checkout_commit(root)}
    script = sccmhunter_script(root)
    if not script:
        return {"status": "FAILED", "detail": f"{root}/sccmhunter.py not found",
                "root": str(root), "commit": _checkout_commit(root)}
    try:
        smoke = subprocess.run([str(interpreter), str(script), "--help"],
                               capture_output=True, text=True, timeout=60, check=False,
                               cwd=str(root))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "FAILED", "detail": f"{type(exc).__name__}: {exc}",
                "root": str(root), "commit": _checkout_commit(root)}
    if smoke.returncode:
        tail = (smoke.stderr or smoke.stdout).strip().splitlines()
        return {"status": "FAILED", "detail": tail[-1] if tail else "help check failed",
                "root": str(root), "commit": _checkout_commit(root)}
    commit = _checkout_commit(root)
    return {"status": "PASS", "detail": f"{root} ({commit[:12]})",
            "root": str(root), "commit": commit}


def _rows(connection, table):
    try:
        cursor = connection.execute(f"SELECT * FROM {table}")
    except sqlite3.Error:
        return []
    columns = [str(item[0]) for item in cursor.description or []]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _host(value):
    return str(value or "").strip().lower()


def parse_find_database(db_path):
    """Normalize the ``find`` SQLite results into bounded SCCM topology."""
    result = {"status": "PASS", "site_codes": [], "management_points": [],
              "distribution_points": [], "site_servers": [], "errors": []}
    path = Path(db_path)
    if not path.is_file():
        result["status"] = "NOT TESTED"
        result["errors"].append("SCCMHunter produced no discovery database")
        return result
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        for row in _rows(connection, "CAS"):
            code = str(row.get("SiteCode") or "").strip()
            if code and code not in result["site_codes"]:
                result["site_codes"].append(code)
        for row in _rows(connection, "ManagementPoints"):
            host = _host(row.get("Hostname"))
            code = str(row.get("SiteCode") or "").strip()
            if not host:
                continue
            result["management_points"].append({"host": host, "site_code": code})
            if code and code not in result["site_codes"]:
                result["site_codes"].append(code)
        for row in _rows(connection, "PXEDistributionPoints"):
            host = _host(row.get("Hostname"))
            if host:
                result["distribution_points"].append({"host": host, "pxe": True})
        for row in _rows(connection, "SiteServers"):
            host = _host(row.get("Hostname"))
            if host:
                result["site_servers"].append({"host": host,
                                               "site_code": str(row.get("SiteCode") or "").strip()})
    finally:
        connection.close()
    for key in ("site_codes",):
        result[key] = sorted(result[key], key=str.casefold)
    for key in ("management_points", "distribution_points", "site_servers"):
        deduped, seen = [], set()
        for item in sorted(result[key], key=lambda entry: entry["host"]):
            if item["host"] in seen:
                continue
            seen.add(item["host"])
            deduped.append(item)
        result[key] = deduped
    return result


def find_database_path(workdir):
    return Path(workdir) / ".sccmhunter" / "logs" / "db" / "find.db"


def build_command(interpreter, script, *, domain, dc_ip, username, password=None, ldaps=False):
    command = [str(interpreter), str(script), COMMAND, "-d", str(domain),
               "-dc-ip", str(dc_ip), "-u", str(username)]
    if ldaps:
        command.append("-ldaps")
    if password is not None:
        command.extend(["-p", str(password)])
    return command


def redact_command(command, password):
    """Return the documented invocation with the password never exposed."""
    redacted, skip = [], False
    for part in command:
        if skip:
            redacted.append("<password>")
            skip = False
            continue
        if password and part == str(password):
            redacted.append("<password>")
            continue
        redacted.append(part)
        if part == "-p":
            skip = True
    return " ".join(redacted)


def run_sccmhunter(domain, dc_ip, username, password, *, timeout=180, workdir,
                   ldaps=False, checkout=None):
    """Run exactly one read-only SCCMHunter ``find`` and normalize the results."""
    root = sccmhunter_root(checkout)
    interpreter = sccmhunter_python(root)
    script = sccmhunter_script(root)
    workdir = Path(workdir)
    if not interpreter or not script:
        return {"status": "NOT TESTED", "commit": _checkout_commit(root),
                "source": "", "command": "", "errors": ["SCCMHunter unavailable"],
                "site_codes": [], "management_points": [], "distribution_points": [],
                "site_servers": []}
    workdir.mkdir(parents=True, exist_ok=True)
    command = build_command(interpreter, script, domain=domain, dc_ip=dc_ip,
                            username=username, password=password, ldaps=ldaps)
    documented = redact_command(command, password)
    # ``find`` takes the password on argv; run it with a redirected HOME so the
    # discovery database cannot land in the operator's home directory.
    environment = dict(os.environ)
    environment["HOME"] = str(workdir)
    try:
        completed = subprocess.run(command, cwd=str(workdir), capture_output=True, text=True,
                                   timeout=float(timeout), check=False, env=environment)
        stdout, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired:
        return {"status": "NOT TESTED", "commit": _checkout_commit(root),
                "source": "SCCMHunter", "command": documented,
                "errors": [f"SCCMHunter timed out after {timeout}s"],
                "site_codes": [], "management_points": [], "distribution_points": [],
                "site_servers": []}
    except OSError as exc:
        return {"status": "NOT TESTED", "commit": _checkout_commit(root),
                "source": "SCCMHunter", "command": documented,
                "errors": [f"{type(exc).__name__}: {exc}"],
                "site_codes": [], "management_points": [], "distribution_points": [],
                "site_servers": []}
    (workdir / "stdout.txt").write_text(
        str(stdout or "").replace(str(password), "<redacted>"), encoding="utf-8", errors="replace")
    (workdir / "stderr.txt").write_text(
        str(stderr or "").replace(str(password), "<redacted>"), encoding="utf-8", errors="replace")
    parsed = parse_find_database(find_database_path(workdir))
    parsed["source"] = "SCCMHunter"
    parsed["command"] = documented
    parsed["commit"] = _checkout_commit(root)
    parsed["returncode"] = returncode
    if returncode and parsed["status"] == "PASS":
        parsed["status"] = "FAILED"
    if returncode and not parsed["errors"]:
        parsed["errors"].append(f"SCCMHunter exit {returncode}")
    return parsed
