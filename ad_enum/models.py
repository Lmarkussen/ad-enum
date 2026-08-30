from dataclasses import dataclass, field


@dataclass
class Template:
    name: str
    display_name: str
    dn: str = ""
    name_flags: int = 0
    enrollment_flags: int = 0
    ekus: list[str] = field(default_factory=list)
    application_policies: list[str] = field(default_factory=list)
    enroll_sids: set[str] = field(default_factory=set)
    enrollment_evidence: dict[str, list[object]] = field(default_factory=dict)
    autoenrollment_sids: set[str] = field(default_factory=set)
    autoenrollment_evidence: dict[str, list[object]] = field(default_factory=dict)
    security_descriptor: object | None = None
    enroll_principals: list[str] = field(default_factory=list)
    manager_approval: bool = False
    authorized_signatures: int = 0
    evidence: dict[str, object] = field(default_factory=dict)
    provenance: list[object] = field(default_factory=list)


@dataclass
class CA:
    name: str
    hostname: str
    dn: str = ""
    templates: list[str] = field(default_factory=list)
    certificate: bytes | None = None
    security_descriptor: object | None = None
    evidence: dict[str, object] = field(default_factory=dict)
    provenance: list[object] = field(default_factory=list)


@dataclass
class Finding:
    template: Template
    ca: CA
    vulnerable: bool
    reasons: list[str] = field(default_factory=list)
    evidence: object | None = None


@dataclass
class ESC1Evidence:
    published_by: list[str]
    subject_supply: bool
    authentication_policy: list[str]
    manager_approval: bool
    authorized_signatures: int
    effective_enrollers: dict[str, list[object]]
    acl_evidence: dict[str, object]
    group_membership_evidence: dict[str, object]
    raw_template_flags: dict[str, int]
    reasons: list[str] = field(default_factory=list)
    vulnerable: bool = False


@dataclass
class PrincipalContext:
    low_privileged_sids: set[str]
    names: dict[str, str] = field(default_factory=dict)

    def name(self, sid):
        return self.names.get(sid, sid)
