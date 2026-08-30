"""Safe, deterministic filesystem layout for a scan."""
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import base64
import json
import re
from pathlib import Path
from uuid import UUID

_SAFE = re.compile(r"[^a-z0-9._-]+")

def canonical_domain(value):
    """Return a safe lowercase DNS-style domain directory component."""
    text = str(value or "").strip().lower()
    if text.upper().startswith("DC="):
        text = ".".join(part.split("=", 1)[1] for part in text.split(",")
                          if part.strip().lower().startswith("dc="))
    text = text.strip(".")
    text = _SAFE.sub("-", text)
    text = text.strip(".-")
    if not text or text in {".", ".."}:
        raise ValueError("domain does not contain a safe workspace name")
    return text

def json_default(value):
    if is_dataclass(value): return asdict(value)
    if isinstance(value, (set, frozenset)): return sorted(value)
    if isinstance(value, (bytes, bytearray)): return {"base64": base64.b64encode(value).decode()}
    if isinstance(value, UUID): return str(value)
    return str(value)

class ScanWorkspace:
    def __init__(self, output_dir, canonical_dns_domain, *, original_target="", scan_id=None):
        self.base = Path(output_dir).expanduser().resolve()
        self.domain = canonical_domain(canonical_dns_domain)
        self.original_target = original_target
        self.scan_id = scan_id or datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        self.root = self.base / self.domain
        self.history_root = self.root / "scans" / self.scan_id
        self.root.mkdir(parents=True, exist_ok=True)
        self.history_root.mkdir(parents=True, exist_ok=True)

    def _module(self, module):
        name = str(module)
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or name in {".", ".."}:
            raise ValueError("unsafe module name")
        return self.root / name

    def module_dir(self, module):
        path = self._module(module); path.mkdir(exist_ok=True); return path

    def raw_dir(self, module):
        path = self.module_dir(module) / "raw"; path.mkdir(exist_ok=True); return path

    def evidence_dir(self, module):
        path = self.module_dir(module) / "evidence"; path.mkdir(exist_ok=True); return path

    def findings_path(self, module, filename="findings.json"):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", filename):
            raise ValueError("unsafe artifact filename")
        return self.module_dir(module) / filename

    def history_module_dir(self, module):
        path = self.history_root / self._module(module).name; path.mkdir(parents=True, exist_ok=True); return path

    def write_json(self, path, value):
        path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, default=json_default, sort_keys=True) + "\n")
        return path

    def write_text(self, path, value):
        path = Path(path); path.parent.mkdir(parents=True, exist_ok=True); path.write_text(value); return path

    def write_text_atomic(self, path, value):
        path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{self.scan_id}.tmp")
        temporary.write_text(value)
        temporary.replace(path)
        return path

    def relative(self, path):
        return Path(path).resolve().relative_to(self.root).as_posix()
