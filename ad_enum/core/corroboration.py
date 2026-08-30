from dataclasses import dataclass, field

@dataclass
class SourceAssessment:
    source: str
    vulnerable: bool | None
    evidence: object = None
    detail: str = ""

@dataclass
class ValidationAssessment:
    validation: str
    result: str
    detail: str = ""

@dataclass
class Corroboration:
    object_name: str
    assessments: list[SourceAssessment] = field(default_factory=list)
    validations: list[ValidationAssessment] = field(default_factory=list)

    def add_validation(self, validation, result, detail=""):
        self.validations.append(ValidationAssessment(validation, result, detail))

    @property
    def status(self):
        values = {a.vulnerable for a in self.assessments if a.vulnerable is not None}
        if len(values) > 1:
            return "disagreement"
        if len(values) == 1 and len(self.assessments) > 1:
            return "corroborated"
        return "single-source"

    @property
    def overall_status(self):
        source_status = self.status
        if any(v.result == "confirmed" for v in self.validations):
            return "live-confirmed disagreement" if source_status == "disagreement" else "live-confirmed"
        if any(v.result == "refuted" for v in self.validations): return "live-refuted"
        return source_status

    def as_dict(self):
        return {"object": self.object_name, "status": self.status, "overall_status": self.overall_status,
                "assessments": [{"source": a.source, "vulnerable": a.vulnerable,
                                  "detail": a.detail, "evidence": a.evidence}
                                 for a in self.assessments],
                "validation": [v.__dict__ for v in self.validations]}
