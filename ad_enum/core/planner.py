from dataclasses import dataclass, field
from enum import Enum
import shutil
from pathlib import Path

def find_executable(name):
    path = shutil.which(name)
    # Debian/Kali packages expose Certipy as certipy-ad while pipx commonly
    # installs the shorter certipy launcher.  Treat these as one capability.
    if not path and name == "certipy": path = shutil.which("certipy-ad")
    if path:
        return path
    candidate = Path.home() / ".local" / "bin" / name
    return str(candidate) if candidate.is_file() else None

class PlanStatus(str, Enum):
    READY = "READY"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_RUN = "NOT RUN"

@dataclass(frozen=True)
class ModuleSpec:
    id: str
    name: str
    category: str
    required_credentials: bool = True
    required_tools: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()

@dataclass
class PlannedModule:
    spec: ModuleSpec
    status: PlanStatus
    reason: str = ""

@dataclass
class ModuleRegistry:
    modules: dict[str, ModuleSpec] = field(default_factory=dict)

    def register(self, spec): self.modules[spec.id] = spec
    @classmethod
    def default(cls):
        r = cls()
        r.register(ModuleSpec("ldap", "Native LDAP", "directory", outputs=("LDAP",)))
        r.register(ModuleSpec("adcs-native", "AD CS native", "adcs", dependencies=("ldap",), outputs=("ADCS",)))
        r.register(ModuleSpec("adcs-certipy", "AD CS Certipy", "adcs", required_tools=("certipy",), dependencies=("ldap",), outputs=("ADCS",)))
        r.register(ModuleSpec("bloodhound", "BloodHound", "directory", required_tools=("bloodhound-python",), outputs=("BloodHound",)))
        r.register(ModuleSpec("ldapdomaindump", "LDAPDomainDump", "directory", required_tools=("ldapdomaindump",), outputs=("LDAPDomainDump",)))
        r.register(ModuleSpec("netexec", "NetExec", "smb", required_tools=("nxc",), outputs=("NetExec",)))
        r.register(ModuleSpec("sccm-discovery", "SCCM discovery", "sccm", outputs=("SCCM",)))
        r.register(ModuleSpec("kerberos", "Kerberos account exposure", "kerberos", dependencies=("ldap",), outputs=("Kerberos",)))
        r.register(ModuleSpec("delegation", "Delegation enumeration", "delegation", dependencies=("ldap",), outputs=("Delegation",)))
        r.register(ModuleSpec("relay", "Relay enumeration", "relay", outputs=("Relay",)))
        return r

class ExecutionPlanner:
    def __init__(self, registry=None, executable_lookup=find_executable):
        self.registry = registry or ModuleRegistry.default(); self.executable_lookup = executable_lookup

    def plan(self, requested=None):
        ids = list(requested or self.registry.modules)
        plan = []
        known = {}
        for module_id in ids:
            spec = self.registry.modules[module_id]
            missing = [tool for tool in spec.required_tools if not self.executable_lookup(tool)]
            blocked = [dep for dep in spec.dependencies if known.get(dep) == PlanStatus.UNAVAILABLE]
            if missing:
                item = PlannedModule(spec, PlanStatus.UNAVAILABLE, "executable not installed: " + ", ".join(missing))
            elif blocked:
                item = PlannedModule(spec, PlanStatus.UNAVAILABLE, "dependency unavailable: " + ", ".join(blocked))
            else: item = PlannedModule(spec, PlanStatus.READY)
            plan.append(item); known[module_id] = item.status
        return plan
