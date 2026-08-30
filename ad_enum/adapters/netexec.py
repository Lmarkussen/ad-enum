from .base import ToolAdapter
from ..inventory import normalize_password_policy, parse_netexec_smb, parse_netexec_shares
from ..access import parse_netexec_auth


SAFE_ACCESS_PROTOCOLS = ("SMB", "LDAP", "SSH", "RDP", "WINRM", "MSSQL")

class NetExecAdapter(ToolAdapter):
    source_name = "netexec"
    executable = "nxc"

    def build_command(self, *, username, password, target):
        return [self.executable, "smb", target, "-u", username, "-p", password, "--no-progress"]

    def build_policy_command(self, *, domain, username, password, target):
        return [self.executable, "ldap", target, "-u", username, "-p", password,
                "-d", domain, "--pass-pol", "--no-progress"]

    def build_access_command(self, *, protocol, username, password, target,
                             domain="", port=None, help_text="", force_kerb=False):
        """Build one authentication-only NetExec attempt.

        The command deliberately contains no module action, command, shell,
        file, or post-authentication option.  Optional quiet flags are added
        only when the installed protocol help advertises them.
        """
        protocol = str(protocol).lower()
        if protocol not in {x.lower() for x in SAFE_ACCESS_PROTOCOLS}:
            raise ValueError(f"unsupported safe access protocol: {protocol}")
        command = [self.executable, protocol, target, "-u", username, "-p", password]
        advertised = str(help_text).lower()
        if domain and ("-d domain" in advertised or "--domain domain" in advertised):
            command.extend(["-d", domain])
        defaults = {"smb": 445, "ldap": 389, "ssh": 22, "rdp": 3389,
                    "winrm": 5985, "mssql": 1433}
        if port and int(port) != defaults.get(protocol) and "--port" in advertised:
            command.extend(["--port", str(port)])
        if "--no-progress" in advertised:
            command.append("--no-progress")
        if "--no-bruteforce" in advertised:
            command.append("--no-bruteforce")
        if force_kerb and "--use-kcache" in advertised:
            command.extend(["-k", "--use-kcache"])
        return command

    def access_help(self, protocol, *, timeout=5):
        """Return protocol help used to gate optional safe flags.

        Failure is non-fatal; the minimal protocol invocation remains the
        only fallback and still performs one bounded authentication attempt.
        """
        executable = self.resolve_executable()
        if not executable:
            return ""
        import subprocess
        try:
            result = subprocess.run([executable, str(protocol).lower(), "--help"],
                                    capture_output=True, text=True, timeout=timeout,
                                    check=False)
            return (result.stdout or "") + (result.stderr or "")
        except (OSError, subprocess.TimeoutExpired):
            return ""

    def run_access_checks(self, *, context, targets):
        """Validate the current scan identity once per observed target/protocol."""
        records, seen = [], set()
        help_cache = {}
        protocol_map = {"SMB": "smb", "LDAP": "ldap", "SSH": "ssh",
                        "RDP": "rdp", "WINRM": "winrm", "MSSQL": "mssql"}
        for item in targets or []:
            service_name = str(item.get("protocol", item.get("service", ""))).upper()
            # NetExec's LDAP adapter has no advertised LDAPS mode in the
            # installed version; do not silently turn an LDAPS observation
            # into an unencrypted or incorrectly configured auth attempt.
            if service_name == "LDAPS":
                continue
            protocol = service_name
            protocol = next((key for key in protocol_map if key in protocol), "")
            if not protocol or protocol not in SAFE_ACCESS_PROTOCOLS:
                continue
            host = item.get("host") or item.get("fqdn") or item.get("ip")
            target = item.get("ip") or host
            if not target:
                continue
            key = (str(target).lower(), protocol)
            if key in seen:
                continue
            seen.add(key)
            if protocol not in help_cache:
                help_cache[protocol] = self.access_help(protocol)
            command = self.build_access_command(
                protocol=protocol, username=context.auth.username,
                password=context.auth.password, target=target, domain=context.domain,
                port=item.get("port"),
                help_text=help_cache[protocol], force_kerb=context.force_kerb)
            try:
                proc = self.execute(command, cwd=context.workspace.raw_dir("NetExec"),
                                    timeout=min(context.timeout, 10),
                                    secrets=(context.auth.password,),
                                    stream=context.tool_output_callback)
                output = self.redact_text((proc.stdout or "") + (proc.stderr or ""),
                                          (context.auth.password,))
                record = parse_netexec_auth(
                    output, protocol=protocol, host=host or target,
                    ip=item.get("ip", target), principal=context.auth.username,
                    source="NetExec")
                record["roles"] = item.get("roles", []) or []
                record["port"] = item.get("port")
                records.append(record)
            except TimeoutError as exc:
                records.append({"host": host or target, "ip": item.get("ip", target),
                                "roles": item.get("roles", []), "protocol": protocol,
                                "port": item.get("port"), "principal": context.auth.username,
                                "authentication": "TIMEOUT", "privilege": "UNKNOWN",
                                "source": "NetExec", "evidence": {},
                                "error_class": type(exc).__name__})
            except (OSError, ImportError) as exc:
                records.append({"host": host or target, "ip": item.get("ip", target),
                                "roles": item.get("roles", []), "protocol": protocol,
                                "port": item.get("port"), "principal": context.auth.username,
                                "authentication": "TOOL FAILURE", "privilege": "UNKNOWN",
                                "source": "NetExec", "evidence": {},
                                "error_class": type(exc).__name__})
            except Exception as exc:
                records.append({"host": host or target, "ip": item.get("ip", target),
                                "roles": item.get("roles", []), "protocol": protocol,
                                "port": item.get("port"), "principal": context.auth.username,
                                "authentication": "AUTH ERROR", "privilege": "UNKNOWN",
                                "source": "NetExec", "evidence": {},
                                "error_class": type(exc).__name__})
        return records

    def run(self, *, context):
        raw = context.raw_dir("NetExec") if hasattr(context, "raw_dir") else context.workspace.raw_dir("NetExec")
        targets = context.targets or [{"ips": [context.dc_ip]}]
        target_values = [ip for item in targets for ip in item.get("ips", [])] or [context.dc_ip]
        command = [self.executable, "smb", *target_values, "-u", context.auth.username,
                   "-p", context.auth.password, "--no-progress"]
        if context.force_kerb: command += ["-k", "--use-kcache"]
        proc = self.execute(command, cwd=raw, timeout=context.timeout, secrets=(context.auth.password,), stream=context.tool_output_callback)
        policy_command = self.build_policy_command(domain=context.domain, username=context.auth.username,
                                                   password=context.auth.password, target=context.dc_ip)
        if context.force_kerb: policy_command += ["-k", "--use-kcache"]
        if context.ldaps: policy_command += ["--use-ldaps"]
        policy = self.execute(policy_command, cwd=raw, timeout=context.timeout, secrets=(context.auth.password,), stream=context.tool_output_callback)
        share_command = [self.executable, "smb", *target_values, "-u", context.auth.username,
                         "-p", context.auth.password, "--shares", "--no-progress"]
        if context.force_kerb: share_command += ["-k", "--use-kcache"]
        shares = self.execute(share_command, cwd=raw, timeout=context.timeout, secrets=(context.auth.password,), stream=context.tool_output_callback)
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
