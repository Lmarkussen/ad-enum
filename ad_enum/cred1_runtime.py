"""Execution-host checks for the CinderPath-derived PXE transport."""
import ipaddress
import platform
import shutil
import socket
import subprocess
from ctypes.util import find_library


def _route_interface(target):
    try:
        address = ipaddress.ip_address(target)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((str(address), 4011))
        sock.close()
        route = shutil.which("ip")
        if route:
            result = subprocess.run([route, "route", "get", str(address)],
                                    capture_output=True, text=True, timeout=2,
                                    check=False)
            fields = result.stdout.split()
            if "dev" in fields:
                return fields[fields.index("dev") + 1]
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return ""


def _effective_capabilities():
    try:
        text = open("/proc/self/status", encoding="ascii").read()
        value = next(line.split(":", 1)[1].strip() for line in text.splitlines()
                     if line.startswith("CapEff:"))
        return int(value, 16)
    except (OSError, StopIteration, ValueError):
        return 0


def check_cred1_runtime(target):
    """Return explicit PXE suitability diagnostics without changing privileges."""
    result = {"status": "READY", "target": str(target), "platform": platform.system(),
              "interface": "", "requirements": [], "reasons": []}
    if result["platform"] != "Linux":
        result["status"] = "NOT TESTED"
        result["reasons"].append("CinderPath PXE transport requires Linux/libpcap")
        return result
    if not find_library("pcap"):
        result["status"] = "NOT TESTED"
        result["reasons"].append("libpcap is unavailable")
    route = _route_interface(target)
    result["interface"] = route
    if not route:
        result["status"] = "NOT TESTED"
        result["reasons"].append("no IPv4 route to the PXE DP")
    if route.startswith(("tailscale", "tun", "tap", "wg")):
        result["status"] = "NOT TESTED"
        result["reasons"].append("routed/tunnel interface cannot provide required Ethernet broadcast capture")
    caps = _effective_capabilities()
    if not (caps & (1 << 13)):
        result["status"] = "NOT TESTED"
        result["reasons"].append("CAP_NET_RAW is not effective")
    if not (caps & (1 << 12)):
        result["status"] = "NOT TESTED"
        result["reasons"].append("CAP_NET_ADMIN is not effective")
    result["requirements"] = ["Linux", "libpcap", "CAP_NET_RAW", "CAP_NET_ADMIN",
                               "direct Ethernet/broadcast visibility"]
    return result
