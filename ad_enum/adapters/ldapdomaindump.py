from .base import ToolAdapter
from ..inventory import parse_ldapdomaindump

class LDAPDomainDumpAdapter(ToolAdapter):
    source_name = "ldapdomaindump"
    executable = "ldapdomaindump"

    def build_command(self, *, domain, username, password, dc_ip, output_dir):
        return [self.executable, "-u", f"{domain}\\{username}", "-p", password,
                "-o", str(output_dir), dc_ip]

    def run(self, *, context):
        if context.force_kerb:
            raise RuntimeError("Kerberos mode unsupported by LDAPDomainDump adapter")
        raw = context.workspace.raw_dir("LDAPDomainDump")
        command = self.build_command(domain=context.domain, username=context.auth.username,
                                     password=context.auth.password, dc_ip=context.dc_ip,
                                     output_dir=raw)
        if context.ldaps: command[-1] = "ldaps://" + command[-1]
        proc = self.execute(command, timeout=context.timeout, secrets=(context.auth.password,), stream=context.tool_output_callback)
        context.workspace.write_text(raw / "stdout.txt", self.redact_text(proc.stdout, (context.auth.password,)))
        context.workspace.write_text(raw / "stderr.txt", self.redact_text(proc.stderr, (context.auth.password,)))
        return {"source": self.source_name, "returncode": proc.returncode,
                "artifact": context.workspace.relative(raw),
                "inventory": parse_ldapdomaindump(raw),
                "provenance": {"source": self.source_name, "command": self.redact_command(command, (context.auth.password,))}}
