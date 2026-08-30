"""AD CS orchestration: native collection plus optional adapter corroboration."""
from .core.coverage import CoverageReport, CoverageStatus
from .core.corroboration import Corroboration, SourceAssessment
from .models import PrincipalContext, CA
from .publication import build_publication_index
from .rules import evaluate_esc1

def scan(cas, templates, *, certipy=None, coverage=None):
    publication, dangling, duplicates = build_publication_index(cas, templates)
    principals = PrincipalContext(set().union(*(t.evidence.get("low_privileged_subject_sids", set())
                                                for t in templates)))
    findings, comparisons = [], {}
    for template in templates:
        for ca in publication.get(template.name, []):
            ok, reasons, evidence = evaluate_esc1(template, ca, principals)
            native = SourceAssessment("ldap-native", ok, evidence, "; ".join(reasons))
            findings.append((template, ca, native))
            comparisons.setdefault(template.name, Corroboration(template.name)).assessments.append(native)
    if certipy:
        for name, assessment in certipy.assessments.items():
            comparisons.setdefault(name, Corroboration(name)).assessments.append(assessment)
    coverage = coverage or CoverageReport()
    coverage.add("AD CS / CA discovery", CoverageStatus.PASS, f"{len(cas)} CA(s)")
    coverage.add("AD CS / templates", CoverageStatus.PASS, f"{len(templates)} template(s)")
    coverage.add("AD CS / publication", CoverageStatus.PASS if not dangling else CoverageStatus.PARTIAL,
                 f"{len(dangling)} dangling reference(s)" if dangling else "CA certificateTemplates relationship")
    coverage.add("AD CS / template ACLs", CoverageStatus.PASS)
    coverage.add("AD CS / Native ESC1", CoverageStatus.PASS)
    coverage.add("AD CS / Native ESC2+", CoverageStatus.NOT_RUN, "not implemented natively")
    # Backward-compatible key for consumers of the pre-source-aware schema.
    # The authoritative status is the Native ESC2+ and Certipy entries above.
    coverage.add("AD CS / ESC2+", CoverageStatus.NOT_RUN, "legacy alias; native rules not implemented")
    coverage.add("AD CS / Certipy vulnerability enumeration", CoverageStatus.PASS if certipy
                 else CoverageStatus.NOT_AVAILABLE,
                 "all Certipy-reported vulnerability IDs ingested" if certipy else "Certipy unavailable")
    coverage.add("AD CS / web enrollment", CoverageStatus.NOT_CHECKED)
    coverage.add("AD CS / Certipy corroboration", CoverageStatus.PASS if certipy
                 else CoverageStatus.NOT_AVAILABLE,
                 "JSON source supplied" if certipy else "optional adapter/input unavailable")
    return findings, comparisons, coverage, dangling, duplicates
