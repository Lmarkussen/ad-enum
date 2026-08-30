"""Certipy adapter.

Certipy is an optional oracle. The adapter consumes its JSON schema and never
uses Certipy's human-readable output as an API.
"""
import json
import os
import subprocess
import tempfile
import shutil
import socket
from dataclasses import dataclass, field
from pathlib import Path
from ..core.provenance import Provenance
from ..core.corroboration import SourceAssessment
from ..models import CA, Template
from .base import ToolAdapter

_EKU_NAMES = {
    "Client Authentication": "1.3.6.1.5.5.7.3.2",
    "Smart Card Logon": "1.3.6.1.4.1.311.20.2.2",
    "KDC Authentication": "1.3.6.1.5.2.3.4",
    "Any Purpose": "2.5.29.37.0",
    "Server Authentication": "1.3.6.1.5.5.7.3.1",
}

@dataclass
class CertipySnapshot:
    cas: list[dict] = field(default_factory=list)
    templates: list[dict] = field(default_factory=list)
    assessments: dict[str, SourceAssessment] = field(default_factory=dict)
    provenance: Provenance = field(default_factory=lambda: Provenance("certipy"))
    diagnostics: list[str] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)

    def vulnerability_records(self):
        """Return every Certipy-reported vulnerability, including unknown IDs."""
        records = []
        for section, items in (("CA", self.cas), ("template", self.templates)):
            for item in items:
                subject = item.get("CA Name") or item.get("Template Name") or item.get("Display Name") or "unknown"
                for identifier, explanation in (item.get("[!] Vulnerabilities") or {}).items():
                    records.append({"rule": str(identifier), "category": "ADCS", "source": "certipy",
                                    "affected_object": subject, "object_type": section,
                                    "explanation": explanation, "evidence": item})
        return records

    def normalized_cas(self):
        return [CA(x.get("CA Name", ""), x.get("DNS Name", ""),
                    templates=[], evidence={"raw": x},
                    provenance=[self.provenance]) for x in self.cas]

    def normalized_templates(self):
        result = []
        for x in self.templates:
            names = x.get("Certificate Authorities", []) or []
            eku = [_EKU_NAMES.get(v, v) for v in x.get("Extended Key Usage", []) or []]
            result.append(Template(
                name=x.get("Template Name", ""), display_name=x.get("Display Name", ""),
                name_flags=sum(x.get("Certificate Name Flag", []) or []),
                enrollment_flags=sum(x.get("Enrollment Flag", []) or []), ekus=eku,
                manager_approval=bool(x.get("Requires Manager Approval", False)),
                authorized_signatures=int(x.get("Authorized Signatures Required", 0) or 0),
                evidence={"raw_certipy": x, "published_cas": names},
                provenance=[self.provenance]))
        return result

class CertipyAdapter(ToolAdapter):
    source_name = "certipy"
    executable = "certipy"

    def from_json(self, data_or_path):
        if isinstance(data_or_path, (str, os.PathLike)):
            data = json.loads(Path(data_or_path).read_text())
            detail = str(data_or_path)
        else:
            data = data_or_path
            detail = "in-memory JSON"
        cas = list((data.get("Certificate Authorities") or {}).values())
        templates = list((data.get("Certificate Templates") or {}).values())
        assessments = {}
        for item in templates:
            name = item.get("Template Name", "")
            vulns = item.get("[!] Vulnerabilities") or {}
            esc1 = any(str(k).upper().startswith("ESC1") for k in vulns)
            # Certipy's JSON only lists vulnerable templates when its finding
            # set contains a vulnerability; absence is a negative observation
            # only for templates that were actually returned by the adapter.
            assessments[name] = SourceAssessment(self.source_name, esc1, item,
                                                  "Certipy JSON")
        return CertipySnapshot(cas, templates, assessments,
                               Provenance(self.source_name, "find -json", detail), raw_data=data)

    def run(self, *, domain, username, password=None, dc_ip=None, executable="certipy",
            extra_args=(), workspace=None, timeout=60, ldaps=False, force_kerb=False):
        """Run `certipy find -json` and parse its generated JSON.

        Password is passed via the process argument only when supplied by the
        caller; this adapter never stores it. Deployments may instead pass
        their own credential mechanism or consume a pre-created JSON file.
        """
        with tempfile.TemporaryDirectory(prefix="ad-enum-certipy-") as td:
            prefix = str(Path(td) / "find")
            account = username if "@" in username else f"{username}@{domain}"
            # Certipy 5.x defaults to LDAPS.  Plain LDAP is the same protocol
            # endpoint used by the native collector and is explicit here so a
            # CA scan does not fail merely because the lab has no usable LDAPS
            # certificate.  Operators can override this via extra_args.
            if executable == "certipy":
                executable = shutil.which("certipy") or shutil.which("certipy-ad") or executable
            cmd = [executable, "find", "-u", account, "-json", "-output", prefix]
            if force_kerb:
                cmd += ["-k", "-no-pass", "-target", socket.getfqdn(dc_ip or domain)]
            cmd += ["-ldap-scheme", "ldaps" if ldaps else "ldap",
                    "-ldap-port", "636" if ldaps else "389"]
            if password is not None and not force_kerb: cmd += ["-p", password]
            if dc_ip: cmd += ["-dc-ip", dc_ip]
            cmd += list(extra_args)
            proc = subprocess.run(cmd, text=True, capture_output=True, check=False, cwd=td, timeout=timeout)
            candidates = [Path(f"{prefix}_Certipy.json"), Path(td) / f"_tmp_{Path(prefix).name}_Certipy.json"]
            candidates.extend(Path(td).rglob("*Certipy.json"))
            candidates.extend(Path(td).parent.glob("*Certipy.json"))
            output = next((p for p in candidates if p.exists()), None)
            if proc.returncode != 0 or output is None:
                raise RuntimeError(f"Certipy JSON collection failed ({proc.returncode}): {proc.stderr[-500:]}")
            snapshot = self.from_json(output)
            safe_cmd = ["<password>" if password is not None and part == password else part for part in cmd]
            snapshot.provenance = Provenance(self.source_name, "find -json", " ".join(safe_cmd))
            if workspace is not None:
                workspace.write_json(workspace.raw_dir("ADCS") / "certipy.json", snapshot.raw_data)
                workspace.write_text(workspace.raw_dir("ADCS") / "certipy.stdout.txt", self.redact_text(proc.stdout, (password,)))
                workspace.write_text(workspace.raw_dir("ADCS") / "certipy.stderr.txt", self.redact_text(proc.stderr, (password,)))
            return snapshot
