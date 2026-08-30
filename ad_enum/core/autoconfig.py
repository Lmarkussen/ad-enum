"""Non-invasive local prerequisites for AD/Kerberos scans."""
import socket

def inspect(dc_ip, domain):
    result = {"requested": True, "dc_ip": dc_ip, "dns": "FAILED", "dc_hostname": "", "time": "NOT CHECKED"}
    try:
        result["dc_hostname"] = socket.gethostbyaddr(dc_ip)[0]
        result["dns"] = "RESOLVED"
    except (OSError, socket.gaierror):
        result["dc_hostname"] = domain
    # Changing system time or /etc/hosts is intentionally not implicit.  The
    # caller receives an explicit state and can preserve/revert operator state.
    return result
