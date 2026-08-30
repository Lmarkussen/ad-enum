"""Ephemeral, scan-scoped Kerberos credential material."""
import atexit, os, re, shutil, socket, subprocess, tempfile

class KerberosSession:
    """Acquire once and expose a temporary ccache to compatible adapters."""
    def __init__(self, username, password, domain, dc_host, timeout=10):
        self.username, self.password, self.domain = username, password, domain
        self.dc_host, self.timeout = dc_host, timeout
        self.ccache = self.krb5_config = None; self._previous = {}; self.active = False

    def acquire(self):
        if self.active: return self
        if not self.domain: raise RuntimeError("Kerberos requires a DNS domain")
        kdc = self.dc_host if re.match(r"^\d+(?:\.\d+){3}$", self.dc_host) else socket.getfqdn(self.dc_host)
        cache = tempfile.NamedTemporaryFile(prefix="ad-enum-", suffix=".ccache", delete=False)
        cache.close(); os.chmod(cache.name, 0o600); self.ccache = cache.name
        conf = tempfile.NamedTemporaryFile(prefix="ad-enum-", suffix=".krb5.conf", mode="w", delete=False)
        realm = self.domain.upper(); lower = self.domain.lower()
        conf.write(f"[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n rdns = false\n\n[realms]\n {realm} = {{\n  kdc = {kdc}\n  admin_server = {kdc}\n }}\n\n[domain_realm]\n .{lower} = {realm}\n {lower} = {realm}\n")
        conf.close(); os.chmod(conf.name, 0o600); self.krb5_config = conf.name
        env = os.environ.copy(); env.update({"KRB5_CONFIG": conf.name, "KRB5CCNAME": cache.name})
        try:
            proc = subprocess.run([shutil.which("kinit") or "/usr/bin/kinit", "-c", cache.name,
                                   f"{self.username}@{realm}"], input=self.password + "\n", text=True,
                                  capture_output=True, timeout=self.timeout, check=False, env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.close(); raise RuntimeError(f"Kerberos credential preflight failed: {exc}") from exc
        if proc.returncode:
            detail = (proc.stderr or proc.stdout)[-300:]; self.close()
            raise RuntimeError(f"Kerberos credential preflight failed: {detail}")
        self._previous = {key: os.environ.get(key) for key in ("KRB5_CONFIG", "KRB5CCNAME")}
        os.environ.update({"KRB5_CONFIG": conf.name, "KRB5CCNAME": cache.name})
        self.active = True; atexit.register(self.close); return self

    def close(self):
        for key, value in self._previous.items():
            if value is None: os.environ.pop(key, None)
            else: os.environ[key] = value
        self._previous = {}
        for path in (self.ccache, self.krb5_config):
            if path:
                try: os.unlink(path)
                except FileNotFoundError: pass
        self.ccache = self.krb5_config = None; self.active = False

    def redacted(self): return {"active": self.active, "ccache": "<ephemeral>", "krb5_config": "<ephemeral>"}
