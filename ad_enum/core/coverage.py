from dataclasses import dataclass, field
from enum import Enum

class CoverageStatus(str, Enum):
    PASS = "PASS"
    PARTIAL = "PARTIAL"
    NOT_RUN = "NOT RUN"
    NOT_CHECKED = "NOT CHECKED"
    NOT_AVAILABLE = "NOT AVAILABLE"
    FAILED = "FAILED"

@dataclass
class CoverageItem:
    name: str
    status: CoverageStatus
    detail: str = ""

@dataclass
class CoverageReport:
    items: list[CoverageItem] = field(default_factory=list)

    def add(self, name, status, detail=""):
        self.items.append(CoverageItem(name, CoverageStatus(status), detail))

    def as_dict(self):
        return {item.name: {"status": item.status.value, "detail": item.detail}
                for item in self.items}

    def render(self, heading="Coverage"):
        lines = [heading]
        for item in self.items:
            suffix = f" ({item.detail})" if item.detail else ""
            lines.append(f"  {item.name} ........ {item.status.value}{suffix}")
        return "\n".join(lines)
