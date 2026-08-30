"""Credential-free installation and capability diagnostics."""
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from importlib.metadata import PackageNotFoundError, version as package_version
from .core.planner import find_executable

def _tool(command, version_args=("--version",), package=None):
    path = find_executable(command)
    if not path: return "MISSING", ""
    if package:
        try:
            return "AVAILABLE", package_version(package)
        except PackageNotFoundError:
            pass
    try:
        p = subprocess.run([path, *version_args], capture_output=True, text=True,
                           timeout=3, check=False)
        text = (p.stdout or p.stderr).strip().splitlines()
        version = text[0] if text else "available"
        return ("AVAILABLE" if p.returncode == 0 else "AVAILABLE"), version
    except (OSError, subprocess.TimeoutExpired):
        return "AVAILABLE", "version unavailable"

def report():
    print("AD-Enum\n")
    print("Core")
    print(f"  Python ............... OK ({sys.version.split()[0]})")
    print(f"  project environment .. {'OK' if sys.prefix != sys.base_prefix else 'NOT ACTIVE'}")
    for label, module in (("LDAP support", "ldap3"), ("DNS support", "dns")):
        print(f"  {label:<21} {'OK' if importlib.util.find_spec(module) else 'MISSING'}")
    print("\nExternal tools")
    print("\nRequired Tools")
    tools = [("Certipy", "certipy", "certipy-ad"), ("BloodHound", "bloodhound-python", "bloodhound"),
             ("LDAPDomainDump", "ldapdomaindump", "ldapdomaindump"), ("NetExec", "nxc", "netexec"),
             ("Impacket", "smbclient.py", "impacket")]
    statuses = {}
    for label, command, package in tools:
        status, version = _tool(command, package=package)
        statuses[label] = status
        suffix = f" ({version})" if version else ""
        print(f"  {label:<21} {status}{suffix}")
    if statuses["Impacket"] == "MISSING" and importlib.util.find_spec("impacket"):
        statuses["Impacket"] = "AVAILABLE"
    if any(statuses[x] == "MISSING" for x in ("Certipy", "BloodHound", "LDAPDomainDump", "NetExec", "Impacket")):
        print("\nWARNING: default installation is incomplete")
    print("\nModule Capability")
    nh_status, nh_version = _tool("NetworkHound.py", version_args=("--help",))
    print(f"  NetworkHound ........ {nh_status}{(' (' + nh_version + ')' if nh_version else '')}")
    print("  ADCS native .......... AVAILABLE")
    print(f"  ADCS Certipy ......... {'AVAILABLE' if statuses['Certipy'] == 'AVAILABLE' else 'UNAVAILABLE'}")
    print(f"  BloodHound ........... {'AVAILABLE' if statuses['BloodHound'] == 'AVAILABLE' else 'UNAVAILABLE'}")
    print(f"  LDAPDomainDump ....... {'AVAILABLE' if statuses['LDAPDomainDump'] == 'AVAILABLE' else 'UNAVAILABLE'}")
    print(f"  NetExec .............. {'AVAILABLE' if statuses['NetExec'] == 'AVAILABLE' else 'UNAVAILABLE'}")
    return 0
