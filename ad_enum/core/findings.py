from dataclasses import dataclass, field

FINDINGS_SCHEMA_VERSION = "1.0"

@dataclass
class NormalizedFinding:
    finding_id: str
    category: str
    rule: str
    title: str
    affected_object: str
    domain: str
    sources: list[dict] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    validation: dict = field(default_factory=dict)
    status: str = "unresolved"
    workspace_artifacts: list[str] = field(default_factory=list)
    first_seen_scan: str = ""
    current_scan: str = ""
    priority: str = "high"

    def as_dict(self):
        return {"schema_version": FINDINGS_SCHEMA_VERSION, **self.__dict__}
