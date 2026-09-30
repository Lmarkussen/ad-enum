"""SCCMSecrets Distribution Point file/index inspection (discovery only).

Only the read-only ``files`` subcommand is ever scheduled: AD-Enum indexes a
Distribution Point and retrieves a bounded set of text/configuration formats.
The ``policies`` subcommand is deliberately not integrated because it registers
a new SCCM device.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path


SOURCE_URL = "https://github.com/synacktiv/SCCMSecrets.git"

# Text/configuration formats only; ``.pfx`` is deliberately excluded so private
# key material is not pulled into the workspace automatically.
DEFAULT_EXTENSIONS = ".txt,.xml,.ini,.conf,.ps1,.bat"
MAX_RECURSION = 6
MAX_SCAN_BYTES = 262144

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_ANONYMOUS_ENABLED = "Anonymous Distribution Point access : [VULNERABLE]"
_ANONYMOUS_DISABLED = "Anonymous Distribution Point access : [NOT VULNERABLE]"
_DONE = "[+] All done. Bye!"
_AUTH_FAILED = "do not allow to successfully authenticate to the distribution point"
_NO_CREDENTIALS = "No credentials provided and Distribution Point does not allow anonymous access"
_VALUE_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|credential|secret|api[-_ ]?key)\b\s*[:=]{1,2}\s*[\"']?([^\s\"'<>;]{4,60})")
_USER_RE = re.compile(r"(?i)\b(username|user|account|login)\b\s*[:=]{1,2}\s*[\"']?([^\s\"'<>;]{2,60})")
_TEXT_SUFFIXES = {".txt", ".xml", ".ini", ".conf", ".ps1", ".bat", ".json", ".csv", ".config"}


def _repo_root(explicit=None):
    return Path(explicit) if explicit else Path(__file__).resolve().parents[1]


def sccmsecrets_root(repo_root=None):
    configured = os.environ.get("SCCMSECRETS_ROOT")
    if configured:
        return Path(configured)
    return _repo_root(repo_root) / ".cache" / "SCCMSecrets"


def sccmsecrets_python(checkout=None):
    base = Path(checkout) if checkout else sccmsecrets_root()
    candidate = base / ".venv" / "bin" / "python3"
    return candidate if candidate.is_file() else None


def sccmsecrets_script(checkout=None):
    base = Path(checkout) if checkout else sccmsecrets_root()
    candidate = base / "SCCMSecrets.py"
    return candidate if candidate.is_file() else None


def _git(root, *args, timeout=10):
    try:
        result = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                                text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip() if not result.returncode else ""


def sccmsecrets_capability(checkout=None):
    """Credential-free installation check used by doctor; never sends traffic."""
    root = sccmsecrets_root(checkout)
    if not (root / ".git").exists():
        return {"status": "NOT AVAILABLE", "detail": f"{root} checkout not found",
                "root": str(root), "commit": ""}
    interpreter = sccmsecrets_python(root)
    if not interpreter:
        return {"status": "NOT AVAILABLE", "detail": f"{root}/.venv/bin/python3 not found",
                "root": str(root), "commit": _git(root, "rev-parse", "HEAD")}
    script = sccmsecrets_script(root)
    if not script:
        return {"status": "FAILED", "detail": f"{root}/SCCMSecrets.py not found",
                "root": str(root), "commit": _git(root, "rev-parse", "HEAD")}
    try:
        smoke = subprocess.run([str(interpreter), str(script), "--help"],
                               capture_output=True, text=True, timeout=60, check=False,
                               cwd=str(root))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "FAILED", "detail": f"{type(exc).__name__}: {exc}",
                "root": str(root), "commit": _git(root, "rev-parse", "HEAD")}
    if smoke.returncode:
        tail = (smoke.stderr or smoke.stdout).strip().splitlines()
        return {"status": "FAILED", "detail": tail[-1] if tail else "help check failed",
                "root": str(root), "commit": _git(root, "rev-parse", "HEAD")}
    commit = _git(root, "rev-parse", "HEAD")
    return {"status": "PASS", "detail": f"{root} ({commit[:12]})",
            "root": str(root), "commit": commit}


def build_command(interpreter, script, *, dp, username=None, password=None,
                  extensions=DEFAULT_EXTENSIONS, max_recursion=MAX_RECURSION):
    command = [str(interpreter), str(script), "files", "-dp", str(dp)]
    if username:
        command.extend(["-u", str(username)])
    if password is not None:
        command.extend(["-p", str(password)])
    return [*command, "-e", str(extensions), "-r", str(int(max_recursion))]


def redact_command(command, password):
    """Return the documented invocation with the password never exposed."""
    if not password:
        return " ".join(str(part) for part in command)
    return " ".join("<password>" if str(part) == str(password) else str(part)
                    for part in command)


def _strip_ansi(text):
    return _ANSI.sub("", str(text or ""))


def _loot_dir(workdir):
    loot_root = Path(workdir) / "loot"
    candidates = [path for path in loot_root.glob("*_files") if path.is_dir()]
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.name)


def _indexed_files(index_path):
    """Return the file entries (leaf nodes) from SCCMSecrets' tree index."""
    if not index_path.is_file():
        return []
    entries = []
    for line in index_path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        leaf = stripped.split("──", 1)[-1].strip() if "──" in stripped else stripped
        if not leaf or leaf.endswith("/"):
            continue
        entries.append(leaf)
    return entries


def _scan_text(path, limit=MAX_SCAN_BYTES):
    try:
        if path.stat().st_size > limit:
            return ""
    except OSError:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _credentials_from(text, *, path, dp):
    values = [(match.group(1), match.group(2)) for match in _VALUE_RE.finditer(text)]
    if not values:
        return []
    accounts = [(match.group(1), match.group(2)) for match in _USER_RE.finditer(text)]
    account = accounts[0][1] if accounts else ""
    return [{"type": f"SCCM DP file {kind.lower()}", "name": kind.lower(),
             "username": account, "value": value,
             "path": path, "dp": dp, "source": "SCCMSecrets"} for kind, value in values]


def parse_files_artifacts(workdir, stdout=""):
    """Normalize the loot/index produced by ``SCCMSecrets.py files``."""
    workdir = Path(workdir)
    text = _strip_ansi(stdout)
    result = {"state": "NOT TESTED", "access": "UNKNOWN", "indexed": 0, "downloaded": 0,
              "interesting": 0, "files": [], "credentials": [], "errors": [],
              "source": "SCCMSecrets", "loot": ""}
    if _ANONYMOUS_ENABLED in text:
        result["access"] = "ANONYMOUS"
    elif _ANONYMOUS_DISABLED in text:
        result["access"] = "AUTHENTICATED"
    loot = _loot_dir(workdir)
    if loot is None:
        if _AUTH_FAILED in text or _NO_CREDENTIALS in text:
            result["state"] = "NOT ACCESSIBLE"
            result["errors"].append("Distribution Point refused the supplied authentication")
        return result
    result["loot"] = loot.name
    index_entries = _indexed_files(loot / "index.txt")
    downloaded = sorted(path for path in loot.rglob("*") if path.is_file()
                        and path.name != "index.txt")
    result["indexed"] = len(index_entries)
    result["downloaded"] = len(downloaded)
    for path in downloaded:
        relative = str(path.relative_to(loot))
        result["files"].append({"path": relative, "size": path.stat().st_size})
    for path in downloaded:
        if path.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        body = _scan_text(path)
        if not body:
            continue
        credentials = _credentials_from(body, path=str(path.relative_to(loot)), dp="")
        if credentials:
            result["interesting"] += 1
            result["credentials"].extend(credentials)
    if result["state"] != "NOT ACCESSIBLE":
        result["state"] = "ACCESSIBLE"
    return result


def run_files(dp, username, password, *, timeout=300, workdir,
              extensions=DEFAULT_EXTENSIONS, max_recursion=MAX_RECURSION, checkout=None):
    """Run exactly one read-only SCCMSecrets ``files`` inspection against a DP."""
    root = sccmsecrets_root(checkout)
    interpreter = sccmsecrets_python(root)
    script = sccmsecrets_script(root)
    workdir = Path(workdir)
    if not interpreter or not script:
        return {"dp": str(dp), "state": "NOT TESTED", "access": "UNKNOWN", "indexed": 0,
                "downloaded": 0, "interesting": 0, "files": [], "credentials": [],
                "errors": ["SCCMSecrets unavailable"], "source": "", "command": "",
                "commit": _git(root, "rev-parse", "HEAD")}
    workdir.mkdir(parents=True, exist_ok=True)
    command = build_command(interpreter, script, dp=dp, username=username, password=password,
                            extensions=extensions, max_recursion=max_recursion)
    documented = redact_command(command, password)
    try:
        completed = subprocess.run(command, cwd=str(workdir), capture_output=True,
                                   text=True, timeout=float(timeout), check=False)
        stdout, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired:
        return {"dp": str(dp), "state": "NOT TESTED", "access": "UNKNOWN", "indexed": 0,
                "downloaded": 0, "interesting": 0, "files": [], "credentials": [],
                "errors": [f"SCCMSecrets timed out after {timeout}s"], "source": "SCCMSecrets",
                "command": documented, "commit": _git(root, "rev-parse", "HEAD")}
    except OSError as exc:
        return {"dp": str(dp), "state": "NOT TESTED", "access": "UNKNOWN", "indexed": 0,
                "downloaded": 0, "interesting": 0, "files": [], "credentials": [],
                "errors": [f"{type(exc).__name__}: {exc}"], "source": "SCCMSecrets",
                "command": documented, "commit": _git(root, "rev-parse", "HEAD")}
    def _redact(value):
        text = _strip_ansi(value)
        return text.replace(str(password), "<redacted>") if password else text
    (workdir / "stdout.txt").write_text(_redact(stdout), encoding="utf-8", errors="replace")
    (workdir / "stderr.txt").write_text(_redact(stderr), encoding="utf-8", errors="replace")
    # SCCMSecrets logs its context lines through ``logging`` (stderr) and only
    # prints progress to stdout, so both streams feed the normalizer.
    parsed = parse_files_artifacts(workdir, "\n".join((stdout or "", stderr or "")))
    parsed["dp"] = str(dp)
    parsed["source"] = "SCCMSecrets"
    parsed["command"] = documented
    parsed["commit"] = _git(root, "rev-parse", "HEAD")
    parsed["returncode"] = returncode
    for entry in parsed["credentials"]:
        entry["dp"] = str(dp)
        entry["path"] = f"{parsed['loot']}/{entry['path']}" if parsed.get("loot") else entry["path"]
    if returncode and parsed["state"] == "NOT TESTED" and not parsed["errors"]:
        parsed["errors"].append(f"SCCMSecrets exit {returncode}")
    return parsed
