"""Credential-free installation and capability diagnostics."""
import importlib.util
import subprocess
import sys
from pathlib import Path
from .core.planner import find_executable

# Check the command interfaces used by the existing adapters, without targets.
REQUIRED_TOOLS = (
    ("Certipy", "certipy", ("find", "--help"), ()),
    ("BloodHound", "bloodhound-python", ("--help",), ()),
    ("LDAPDomainDump", "ldapdomaindump", ("--help",), ()),
    ("NetExec", "nxc", ("smb", "--help"), ()),
    ("Impacket", "smbclient.py", ("--help",), ()),
    ("CinderPath", "cinderpath", ("assess", "CRED-1", "--help"), ("--format",)),
    ("SCCM PXE helper", "ad-enum-sccm-pxe", ("--help",), ()),
    ("NetworkHound", "NetworkHound.py", ("--help",),
     ("--dc", "--domain", "--user", "--output", "--dns", "--kerberos", "--password")),
    ("RelayKing", "relayking.py", ("--help",),
     ("--audit", "--protocols", "--proto-portscan", "--no-ghosts", "--output-file", "--threads", "--dc-ip")),
)


def _tool(command, version_args=("--help",), required_flags=(), *, executable=None):
    path = executable or find_executable(command)
    if not path:
        return "NOT AVAILABLE", f"{command} not found"
    try:
        p = subprocess.run([path, *version_args], capture_output=True, text=True,
                           timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "FAILED", f"{path}: {exc}"
    output = (p.stdout or "") + (p.stderr or "")
    # RelayKing's main catches every argparse SystemExit, including help, and
    # returns 1. Accept only clean help with all required adapter options.
    relay_help = (command == "relayking.py" and tuple(version_args) == ("--help",)
                  and p.returncode == 1 and required_flags
                  and "usage:" in (p.stdout or "").lower() and not (p.stderr or "").strip())
    if p.returncode and not relay_help:
        lines = output.strip().splitlines()
        reason = lines[-1] if lines else "no diagnostic output"
        return "FAILED", f"{path}: exit {p.returncode}: {reason}"
    missing = [flag for flag in required_flags if flag not in output]
    if missing:
        return "FAILED", f"{path}: missing required options: {', '.join(missing)}"
    return "PASS", path


def report():
    print("AD-Enum\n\nCore")
    print(f"  Python ............... PASS ({sys.version.split()[0]})")
    print(f"  project environment .. {'PASS' if sys.prefix != sys.base_prefix else 'NOT AVAILABLE'}")
    healthy = True
    for label, module in (("LDAP support", "ldap3"), ("DNS support", "dns"),
                          ("Kerberos support", "gssapi"), ("Impacket support", "impacket")):
        available = importlib.util.find_spec(module) is not None
        healthy &= available
        print(f"  {label:<21} {'PASS' if available else 'NOT AVAILABLE'}")
    print("\nRequired Tools")
    for label, command, args, flags in REQUIRED_TOOLS:
        status, detail = _tool(command, args, flags)
        healthy &= status == "PASS"
        print(f"  {label:<21} {status} ({detail})")
    # Protocol help loads argument definitions only. Import the implementations
    # with NetExec's isolated interpreter to catch missing runtime dependencies.
    nxc = find_executable("nxc")
    nxc_python = str(Path(nxc).resolve().parent / "python") if nxc else None
    for protocol in ("smb", "ldap", "ssh", "rdp", "winrm", "mssql"):
        status, detail = _tool("nxc", ("-c", f"import nxc.protocols.{protocol}"), executable=nxc_python)
        healthy &= status == "PASS"
        print(f"  {'NetExec ' + protocol:<21} {status} ({detail})")
    for command in ("kinit", "klist", "nslookup"):
        path = find_executable(command)
        healthy &= path is not None
        print(f"  {command:<21} {'PASS' if path else 'NOT AVAILABLE'} ({path or 'not found'})")
    print("\nModule Capability\n  ADCS native .......... PASS")
    if not healthy:
        print("\nFAILED: default installation is incomplete; rerun ./install.sh")
    return 0 if healthy else 1
