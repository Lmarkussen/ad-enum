"""Non-invasive local prerequisites for AD/Kerberos scans."""
import socket
import re
import os
import shutil
import subprocess
from pathlib import Path

HOSTS_BEGIN = "# AD-Enum managed hosts begin"
HOSTS_END = "# AD-Enum managed hosts end"

def format_skew(seconds):
    from .kerberos_errors import format_skew as _format
    return _format(seconds)

def measure_time_skew(dc_ip, timeout=5, runner=subprocess.run):
    """Measure NTP offset without changing local system state."""
    ntpdate = shutil.which("ntpdate")
    if not ntpdate:
        return {"status": "UNAVAILABLE", "error": "ntpdate is not installed"}
    try:
        proc = runner([ntpdate, "-q", dc_ip], capture_output=True, text=True,
                      timeout=timeout, check=False)
        raw = (proc.stdout or "") + (proc.stderr or "")
        # ntpdate emits either `offset N sec` or the compact
        # `(<timezone>) N +/- ...` form, depending on version.
        match = re.search(r"\boffset\s+([-+]?\d+(?:\.\d+)?)\s+sec", raw, re.I)
        if not match:
            match = re.search(r"\)\s*([-+]?\d+(?:\.\d+)?)\s+\+/-", raw)
        result = {"status": "MEASURED" if proc.returncode == 0 and match else "FAILED",
                  "raw": raw[-500:]}
        if match:
            result["skew_seconds"] = float(match.group(1))
            result["skew_human"] = format_skew(result["skew_seconds"])
        elif proc.returncode != 0:
            result["error"] = raw[-200:].strip()
        return result
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "FAILED", "error": str(exc)}

def sync_time(dc_ip, timeout=15, runner=subprocess.run):
    """One-shot synchronization, explicitly requested by the operator."""
    ntpdate = shutil.which("ntpdate")
    if not ntpdate:
        return {"status": "UNAVAILABLE", "error": "ntpdate is not installed"}
    command = [ntpdate, "-u", dc_ip]
    # Most Kali installs require root for settimeofday.  -n prevents a hidden
    # password prompt; the operator can grant sudo explicitly and retry.
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        command = ["sudo", "-n", *command]
    try:
        proc = runner(command, capture_output=True, text=True, timeout=timeout, check=False)
        raw = ((proc.stdout or "") + (proc.stderr or ""))[-500:]
        return {"status": "SYNCED" if proc.returncode == 0 else "FAILED",
                "command": ["sudo", "ntpdate", "-u", dc_ip] if command[0] == "sudo" else command,
                "raw": raw, "error": raw if proc.returncode else ""}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "FAILED", "error": str(exc)}

def restore_hosts(path="/etc/hosts"):
    """Remove only an AD-Enum-managed block; never restore unrelated lines."""
    target = Path(path)
    if not target.exists(): return {"status": "NOT FOUND", "path": str(target)}
    text = target.read_text()
    if HOSTS_BEGIN not in text or HOSTS_END not in text:
        return {"status": "NO AD-ENUM CHANGES", "path": str(target)}
    before, remainder = text.split(HOSTS_BEGIN, 1)
    _, after = remainder.split(HOSTS_END, 1)
    target.write_text(before.rstrip() + "\n" + after.lstrip())
    return {"status": "RESTORED", "path": str(target)}

def inspect(dc_ip, domain):
    result = {"requested": True, "dc_ip": dc_ip, "dns": "FAILED", "dc_hostname": "", "time": "NOT CHECKED"}
    try:
        result["dc_hostname"] = socket.gethostbyaddr(dc_ip)[0]
        result["dns"] = "RESOLVED"
    except (OSError, socket.gaierror):
        result["dc_hostname"] = domain
    measured = measure_time_skew(dc_ip)
    result["time"] = measured.pop("status")
    result.update(measured)
    # Changing system time or /etc/hosts is intentionally not implicit.  The
    # caller receives an explicit state; synchronization needs an operator-
    # approved privileged action and is reported as a future explicit step.
    return result
