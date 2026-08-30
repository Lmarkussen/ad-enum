"""Non-invasive local prerequisites for AD/Kerberos scans."""
import socket
import re
import shutil
import subprocess

def inspect(dc_ip, domain):
    result = {"requested": True, "dc_ip": dc_ip, "dns": "FAILED", "dc_hostname": "", "time": "NOT CHECKED"}
    try:
        result["dc_hostname"] = socket.gethostbyaddr(dc_ip)[0]
        result["dns"] = "RESOLVED"
    except (OSError, socket.gaierror):
        result["dc_hostname"] = domain
    ntpdate = shutil.which("ntpdate")
    if ntpdate:
        try:
            proc = subprocess.run([ntpdate, "-q", dc_ip], capture_output=True, text=True, timeout=5, check=False)
            line = (proc.stdout + proc.stderr).strip()
            match = re.search(r"\(([-+]?\d+(?:\.\d+)?)\s*[-+]", line)
            result["time"] = "MEASURED" if proc.returncode == 0 else "FAILED"
            if match: result["skew_seconds"] = float(match.group(1))
            result["time_raw"] = line[-500:]
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["time"] = "FAILED"; result["time_error"] = str(exc)
    # Changing system time or /etc/hosts is intentionally not implicit.  The
    # caller receives an explicit state; synchronization needs an operator-
    # approved privileged action and is reported as a future explicit step.
    return result
