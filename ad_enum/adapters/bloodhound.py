from .base import ToolAdapter
from ..inventory import parse_bloodhound
from pathlib import Path

class BloodHoundAdapter(ToolAdapter):
    source_name = "bloodhound"
    executable = "bloodhound-python"

    def build_command(self, *, domain, username, password, dc_ip, output_dir):
        return [self.executable, "-d", domain, "-u", username, "-p", password,
                "-ns", dc_ip, "-c", "All", "--zip", "-op", str(Path(output_dir) / "bloodhound")]

    def run(self, *, context):
        raw = context.workspace.raw_dir("BloodHound")
        command = self.build_command(domain=context.domain, username=context.auth.username,
                                     password=context.auth.password, dc_ip=context.dc_ip,
                                     output_dir=raw)
        if context.force_kerb: command.append("-k")
        if context.ldaps: command.append("--use-ldaps")
        proc = self.execute(command, timeout=context.timeout, secrets=(context.auth.password,))
        context.workspace.write_text(raw / "stdout.txt", self.redact_text(proc.stdout, (context.auth.password,)))
        context.workspace.write_text(raw / "stderr.txt", self.redact_text(proc.stderr, (context.auth.password,)))
        return {"source": self.source_name, "returncode": proc.returncode,
                "artifact": context.workspace.relative(raw), "collection": "All",
                "inventory": parse_bloodhound(raw),
                "provenance": {"source": self.source_name, "command": self.redact_command(command, (context.auth.password,))}}
