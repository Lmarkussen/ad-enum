from .base import ToolAdapter
from ..inventory import normalize_password_policy, parse_netexec_smb, parse_netexec_shares

class NetExecAdapter(ToolAdapter):
    source_name = "netexec"
    executable = "nxc"

    def build_command(self, *, username, password, target):
        return [self.executable, "smb", target, "-u", username, "-p", password, "--no-progress"]

    def build_policy_command(self, *, domain, username, password, target):
        return [self.executable, "ldap", target, "-u", username, "-p", password,
                "-d", domain, "--pass-pol", "--no-progress"]

    def run(self, *, context):
        raw = context.raw_dir("NetExec") if hasattr(context, "raw_dir") else context.workspace.raw_dir("NetExec")
        targets = context.targets or [{"ips": [context.dc_ip]}]
        target_values = [ip for item in targets for ip in item.get("ips", [])] or [context.dc_ip]
        command = [self.executable, "smb", *target_values, "-u", context.auth.username,
                   "-p", context.auth.password, "--no-progress"]
        if context.force_kerb: command += ["-k", "--use-kcache"]
        proc = self.execute(command, cwd=raw, timeout=context.timeout, secrets=(context.auth.password,))
        policy_command = self.build_policy_command(domain=context.domain, username=context.auth.username,
                                                   password=context.auth.password, target=context.dc_ip)
        if context.force_kerb: policy_command += ["-k", "--use-kcache"]
        if context.ldaps: policy_command += ["--use-ldaps"]
        policy = self.execute(policy_command, cwd=raw, timeout=context.timeout, secrets=(context.auth.password,))
        share_command = [self.executable, "smb", *target_values, "-u", context.auth.username,
                         "-p", context.auth.password, "--shares", "--no-progress"]
        if context.force_kerb: share_command += ["-k", "--use-kcache"]
        shares = self.execute(share_command, cwd=raw, timeout=context.timeout, secrets=(context.auth.password,))
        safe_smb = self.redact_text(proc.stdout, (context.auth.password,))
        safe_policy = self.redact_text(policy.stdout, (context.auth.password,))
        normalized_policy = normalize_password_policy(policy.stdout)
        normalized_policy["raw_excerpt"] = safe_policy[-4000:]
        context.workspace.write_text(raw / "smb.stdout.txt", safe_smb)
        context.workspace.write_text(raw / "smb.stderr.txt", self.redact_text(proc.stderr, (context.auth.password,)))
        context.workspace.write_text(raw / "password-policy.stdout.txt", safe_policy)
        context.workspace.write_text(raw / "password-policy.stderr.txt", self.redact_text(policy.stderr, (context.auth.password,)))
        context.workspace.write_text(raw / "shares.stdout.txt", self.redact_text(shares.stdout, (context.auth.password,)))
        context.workspace.write_text(raw / "shares.stderr.txt", self.redact_text(shares.stderr, (context.auth.password,)))
        artifact = raw / "smb.stdout.txt"
        context.workspace.write_text(raw / "stdout.txt", safe_smb)
        context.workspace.write_text(raw / "stderr.txt", self.redact_text(proc.stderr, (context.auth.password,)))
        return {"source": self.source_name, "returncode": proc.returncode,
                "artifact": context.workspace.relative(artifact),
                "hosts": parse_netexec_smb(safe_smb),
                "shares": parse_netexec_shares(self.redact_text(shares.stdout, (context.auth.password,))),
                "password_policy": normalized_policy,
                "provenance": {"source": self.source_name,
                               "command": self.redact_command(command, (context.auth.password,)),
                               "policy_command": self.redact_command(policy_command, (context.auth.password,))}}
