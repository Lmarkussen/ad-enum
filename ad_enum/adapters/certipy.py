"""Certipy adapter.

Certipy is an optional oracle. JSON remains the primary input, with a narrow
human-readable fallback for CA evidence that Certipy omits from JSON output.
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
    template_enumeration_state: str = "NOT OBSERVED"

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

    @staticmethod
    def _text_values(lines, start, base_indent):
        """Return indented scalar/list values and the first following field."""
        values = []
        index = start
        while index < len(lines):
            line = lines[index]
            if not line.strip():
                index += 1
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= base_indent:
                break
            values.append(line.strip())
            index += 1
        return values, index

    @staticmethod
    def _text_scalar(values):
        if not values:
            return ""
        return values[0] if len(values) == 1 else values

    @classmethod
    def _parse_text_ca(cls, lines, start, end):
        """Parse one indented Certipy CA block without depending on spacing."""
        ca = {"Access Rights": {}, "[!] Vulnerabilities": {}}
        index = start
        while index < end:
            line = lines[index]
            if not line.strip():
                index += 1
                continue
            indent = len(line) - len(line.lstrip())
            text = line.strip()
            if indent == 4 and text.endswith(":"):
                key = text[:-1]
                values, index = cls._text_values(lines, index + 1, indent)
                if key in {"CA Name", "DNS Name", "Certificate Subject", "Owner"}:
                    ca[key] = cls._text_scalar(values)
                elif key in {"User Enrollable Principals", "User ACL Principals"}:
                    ca[key] = values
                continue
            if indent == 4 and text.rstrip(":") == "Permissions":
                index += 1
                while index < end:
                    nested = lines[index]
                    if not nested.strip():
                        index += 1
                        continue
                    nested_indent = len(nested) - len(nested.lstrip())
                    nested_text = nested.strip()
                    if nested_indent <= 4:
                        break
                    if nested_indent == 6 and nested_text.rstrip(":") == "Access Rights":
                        index += 1
                        while index < end:
                            right_line = lines[index]
                            if not right_line.strip():
                                index += 1
                                continue
                            right_indent = len(right_line) - len(right_line.lstrip())
                            right_text = right_line.strip()
                            if right_indent <= 6:
                                break
                            if right_indent == 8 and right_text.endswith(":"):
                                right = right_text[:-1]
                                values, index = cls._text_values(lines, index + 1, right_indent)
                                ca["Access Rights"][right] = values
                                continue
                            index += 1
                        continue
                    if nested_indent == 6 and nested_text == "Owner:":
                        values, index = cls._text_values(lines, index + 1, nested_indent)
                        if values:
                            ca["Owner"] = cls._text_scalar(values)
                        continue
                    index += 1
                continue
            if indent == 4 and text.rstrip(":") == "Vulnerabilities":
                index += 1
                while index < end:
                    vulnerability = lines[index]
                    if not vulnerability.strip():
                        index += 1
                        continue
                    vulnerability_indent = len(vulnerability) - len(vulnerability.lstrip())
                    vulnerability_text = vulnerability.strip()
                    if vulnerability_indent <= 4:
                        break
                    if vulnerability_indent == 6 and vulnerability_text.endswith(":"):
                        rule = vulnerability_text[:-1]
                        values, index = cls._text_values(lines, index + 1, vulnerability_indent)
                        ca["[!] Vulnerabilities"][rule] = cls._text_scalar(values)
                        continue
                    index += 1
                continue
            index += 1
        if not ca["Access Rights"]:
            ca.pop("Access Rights")
        if not ca["[!] Vulnerabilities"]:
            ca.pop("[!] Vulnerabilities")
        return ca

    @classmethod
    def _parse_text_output(cls, text):
        """Parse the CA/evidence portions of Certipy's human-readable output."""
        lines = str(text or "").splitlines()
        cas = []
        template_state = "NOT OBSERVED"
        index = 0
        while index < len(lines):
            line = lines[index]
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            if stripped.rstrip(":") == "Certificate Authorities" and indent == 0:
                index += 1
                while index < len(lines):
                    candidate = lines[index]
                    if not candidate.strip():
                        index += 1
                        continue
                    candidate_indent = len(candidate) - len(candidate.lstrip())
                    candidate_text = candidate.strip()
                    if candidate_indent == 0:
                        break
                    if candidate_indent == 2 and candidate_text.isdigit():
                        start = index + 1
                        end = start
                        while end < len(lines):
                            next_line = lines[end]
                            if next_line.strip():
                                next_indent = len(next_line) - len(next_line.lstrip())
                                if next_indent <= 2:
                                    break
                            end += 1
                        cas.append(cls._parse_text_ca(lines, start, end))
                        index = end
                        continue
                    index += 1
                continue
            if stripped.rstrip(":") == "Certificate Templates" and indent == 0:
                values, index = cls._text_values(lines, index + 1, indent)
                if any("could not find any certificate templates" in value.casefold()
                       for value in values):
                    template_state = "UNAVAILABLE"
                elif values:
                    template_state = "AVAILABLE"
                else:
                    template_state = "UNAVAILABLE"
                continue
            index += 1
        return cas, template_state

    def from_text(self, text, *, detail="human-readable output"):
        cas, template_state = self._parse_text_output(text)
        assessments = {}
        return CertipySnapshot(cas=cas, assessments=assessments,
                               provenance=Provenance(self.source_name, "find", detail),
                               raw_data={}, template_enumeration_state=template_state)

    @staticmethod
    def _merge_text_data(snapshot, text_snapshot):
        """Fill missing JSON fields from stdout while preserving JSON as primary."""
        by_name = {str(item.get("CA Name", "")).casefold(): item for item in snapshot.cas
                   if item.get("CA Name")}
        by_dns = {str(item.get("DNS Name", "")).casefold(): item for item in snapshot.cas
                  if item.get("DNS Name")}
        for parsed in text_snapshot.cas:
            existing = by_name.get(str(parsed.get("CA Name", "")).casefold())
            if existing is None:
                existing = by_dns.get(str(parsed.get("DNS Name", "")).casefold())
            if existing is None:
                snapshot.cas.append(parsed)
                existing = parsed
            for key, value in parsed.items():
                if key not in existing or existing[key] in (None, "", [], {}):
                    existing[key] = value
                elif isinstance(existing[key], dict) and isinstance(value, dict):
                    for nested_key, nested_value in value.items():
                        existing[key].setdefault(nested_key, nested_value)
            if existing.get("CA Name"):
                by_name[str(existing["CA Name"]).casefold()] = existing
            if existing.get("DNS Name"):
                by_dns[str(existing["DNS Name"]).casefold()] = existing
        if snapshot.template_enumeration_state == "NOT OBSERVED":
            snapshot.template_enumeration_state = text_snapshot.template_enumeration_state

    def from_json(self, data_or_path):
        if isinstance(data_or_path, (str, os.PathLike)):
            text = Path(data_or_path).read_text()
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return self.from_text(text, detail=str(data_or_path))
            detail = str(data_or_path)
        else:
            data = data_or_path
            detail = "in-memory JSON"
        cas = list((data.get("Certificate Authorities") or {}).values())
        template_section = data.get("Certificate Templates")
        templates = list((template_section or {}).values())
        template_state = ("AVAILABLE" if templates else
                          ("UNAVAILABLE" if "Certificate Templates" in data else "NOT OBSERVED"))
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
                               Provenance(self.source_name, "find -json", detail), raw_data=data,
                               template_enumeration_state=template_state)

    def run(self, *, domain, username, password=None, dc_ip=None, executable="certipy",
            extra_args=(), workspace=None, timeout=60, ldaps=False, force_kerb=False, stream=None):
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
            proc = self.execute(cmd, cwd=td, timeout=timeout, secrets=((password,) if password else ()), stream=stream)
            candidates = [Path(f"{prefix}_Certipy.json"), Path(td) / f"_tmp_{Path(prefix).name}_Certipy.json"]
            candidates.extend(Path(td).rglob("*Certipy.json"))
            candidates.extend(Path(td).parent.glob("*Certipy.json"))
            output = next((p for p in candidates if p.exists()), None)
            if proc.returncode != 0 or output is None:
                raise RuntimeError(f"Certipy JSON collection failed ({proc.returncode}): {proc.stderr[-500:]}")
            snapshot = self.from_json(output)
            self._merge_text_data(snapshot, self.from_text(proc.stdout))
            safe_cmd = ["<password>" if password is not None and part == password else part for part in cmd]
            snapshot.provenance = Provenance(self.source_name, "find -json", " ".join(safe_cmd))
            if workspace is not None:
                workspace.write_json(workspace.raw_dir("ADCS") / "certipy.json", snapshot.raw_data)
                workspace.write_text(workspace.raw_dir("ADCS") / "certipy.stdout.txt", self.redact_text(proc.stdout, (password,)))
                workspace.write_text(workspace.raw_dir("ADCS") / "certipy.stderr.txt", self.redact_text(proc.stderr, (password,)))
            return snapshot
