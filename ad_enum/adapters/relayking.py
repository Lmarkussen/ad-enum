"""Safe RelayKing exposure adapter; never enables coercion or relay actions."""
from pathlib import Path
from .base import ToolAdapter


class RelayKingAdapter(ToolAdapter):
    source_name = "relayking"
    executable = "relayking.py"

    def resolve_executable(self):
        path = super().resolve_executable()
        if path: return path
        candidate = Path.home() / "RelayKing-Depth" / "relayking.py"
        return str(candidate) if candidate.is_file() else None

    def run(self, *, context):
        raw = context.workspace.raw_dir("Relay")
        output = raw / "relayking"
        command = [self.executable, "-u", context.auth.username, "-p", context.auth.password,
                   "-d", context.domain, "--dc-ip", context.dc_ip, "--audit",
                   "--protocols", "smb,ldap,ldaps,mssql,http,https", "--proto-portscan",
                   "--no-ghosts", "-o", "json", "--output-file", str(output), "--threads", "5"]
        if context.force_kerb: command += ["-k"]
        proc = self.execute(command, timeout=context.timeout, secrets=(context.auth.password,), stream=context.tool_output_callback)
        safe_stdout = self.redact_text(proc.stdout, (context.auth.password,))
        safe_stderr = self.redact_text(proc.stderr, (context.auth.password,))
        context.workspace.write_text(raw / "stdout.txt", safe_stdout)
        context.workspace.write_text(raw / "stderr.txt", safe_stderr)
        json_path = Path(str(output) + ".json")
        data = None
        if json_path.exists():
            import json
            try: data = json.loads(json_path.read_text())
            except (OSError, ValueError): data = None
        return {"source": self.source_name, "returncode": proc.returncode,
                "artifact": context.workspace.relative(raw), "json": data,
                "provenance": {"source": self.source_name,
                               "command": self.redact_command(command, (context.auth.password,)),
                               "safe_mode": True}}
