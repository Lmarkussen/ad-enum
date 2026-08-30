from pathlib import Path
from .base import ToolAdapter
from ..network import parse_networkhound


class NetworkHoundAdapter(ToolAdapter):
    """Optional topology-only NetworkHound adapter (no port/shadow-IT scan)."""
    source_name = "networkhound"
    executable = "NetworkHound.py"

    def resolve_executable(self):
        path = super().resolve_executable()
        if path: return path
        candidate = Path.home() / "NetworkHound" / "NetworkHound.py"
        return str(candidate) if candidate.is_file() else None

    def run(self, *, context):
        path = self.resolve_executable()
        if not path: raise FileNotFoundError("NetworkHound.py is not installed")
        output = context.workspace.raw_dir("NetworkHound") / "networkhound.json"
        runner = str(Path(path).parent / ".venv" / "bin" / "python")
        command = ([runner, path] if Path(runner).is_file() else [path]) + [
                   "--dc", context.dc_hostname or context.dc_ip, "--domain", context.domain,
                   "--user", context.auth.username, "--output", str(output), "--dns", context.dc_ip]
        if context.force_kerb: command.append("--kerberos")
        else: command.extend(["--password", context.auth.password])
        proc = self.execute(command, timeout=context.timeout, secrets=(context.auth.password,))
        import json
        data = json.loads(output.read_text()) if output.is_file() else {}
        return {"source": "networkhound", "raw": data,
                "inventory": parse_networkhound(data),
                "stdout": self.redact_text(proc.stdout, (context.auth.password,)),
                "stderr": self.redact_text(proc.stderr, (context.auth.password,))}
