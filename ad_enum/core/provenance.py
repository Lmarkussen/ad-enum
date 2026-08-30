from dataclasses import dataclass, field

@dataclass(frozen=True)
class Provenance:
    source: str
    collector: str = ""
    object_id: str = ""
    detail: str = ""

@dataclass
class Observation:
    value: object
    provenance: list[Provenance] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
