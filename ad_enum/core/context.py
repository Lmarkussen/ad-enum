from dataclasses import dataclass, field

@dataclass
class AuthContext:
    username: str
    password: str = field(repr=False)
    domain: str = ""

    def redacted(self):
        return {"username": self.username, "domain": self.domain, "password": "<redacted>"}

    def __repr__(self):
        return f"AuthContext(username={self.username!r}, domain={self.domain!r}, password=<redacted>)"

@dataclass
class ScanContext:
    domain: str
    dc_ip: str
    auth: AuthContext = field(repr=False)
    workspace: object = field(repr=False)
    timeout: float = 10
    scan_id: str = ""
    targets: list = field(default_factory=list)
    ldaps: bool = False
    force_kerb: bool = False
    dc_hostname: str = ""
    auto_config: dict = field(default_factory=dict)
    kerberos_session: object = field(default=None, repr=False)

    def redacted(self):
        return {"domain": self.domain, "dc_ip": self.dc_ip, "auth": self.auth.redacted(),
                "timeout": self.timeout, "scan_id": self.scan_id,
                "ldaps": self.ldaps, "force_kerb": self.force_kerb,
                "dc_hostname": self.dc_hostname, "auto_config": self.auto_config,
                "kerberos": self.kerberos_session.redacted() if self.kerberos_session else None}

    def __repr__(self):
        return f"ScanContext(domain={self.domain!r}, dc_ip={self.dc_ip!r}, auth=<redacted>, workspace=<workspace>)"
