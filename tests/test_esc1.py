import struct
import pytest
from uuid import UUID
from ad_enum.models import CA, PrincipalContext, Template
from ad_enum.rules import classify_esc1, ENROLLEE_SUPPLIES_SUBJECT, CT_FLAG_PEND_ALL_REQUESTS
from ad_enum.security import parse_security_descriptor, ENROLL_GUID, TEMPLATE_CLASS_GUID
from ad_enum.rights import effective_enrollment
from ad_enum.fixtures import collect_fixture
from ad_enum.publication import build_publication_index
from ad_enum.models import CA

P = PrincipalContext({"S-1-5-11"})
CA0 = CA("LabCA", "dc.sccm.lab")

def t(**kw):
    base = dict(name="T", display_name="T", name_flags=ENROLLEE_SUPPLIES_SUBJECT,
                ekus=["1.3.6.1.5.5.7.3.2"], enroll_sids={"S-1-5-11"})
    base.update(kw); return Template(**base)

def test_vulnerable():
    ok, reasons = classify_esc1(t(), CA0, P); assert ok; assert "authentication" in reasons[-1]
def test_subject_required():
    ok, _ = classify_esc1(t(name_flags=0), CA0, P); assert not ok
def test_no_auth_eku():
    ok, _ = classify_esc1(t(ekus=["1.2.3"]), CA0, P); assert not ok
def test_manager_approval():
    ok, _ = classify_esc1(t(enrollment_flags=CT_FLAG_PEND_ALL_REQUESTS), CA0, P); assert not ok
def test_authorized_signature():
    ok, _ = classify_esc1(t(authorized_signatures=1), CA0, P); assert not ok
def test_privileged_only():
    ok, _ = classify_esc1(t(enroll_sids={"S-1-5-21-1-2-3-512"}), CA0, P); assert not ok
def test_multiple_enrollment_sids():
    ok, _ = classify_esc1(t(enroll_sids={"S-1-5-21-1-2-3-512", "S-1-5-11"}), CA0, P); assert ok

def sid(value):
    parts = value.split("-"); return bytes([int(parts[1]), len(parts)-3]) + int(parts[2]).to_bytes(6, "big") + b"".join(struct.pack("<I", int(x)) for x in parts[3:])

def descriptor(*aces):
    acl = struct.pack("<BBHHH", 2, 0, 8 + sum(len(x) for x in aces), len(aces), 0) + b"".join(aces)
    return struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20) + acl

def allow(s, mask=0x100, obj=None, typ=0, flags=0):
    sb = sid(s)
    if obj:
        body = struct.pack("<BBHII", 5, flags, 28 + len(sb), mask, 1) + UUID(obj).bytes_le + sb
    else:
        body = struct.pack("<BBHI", typ, flags, 8 + len(sb), mask) + sb
    return body

def deny(s, mask=0x100): return allow(s, mask, typ=1)

def test_sd_parser_decodes_object_ace():
    value = descriptor(allow("S-1-5-11", obj=str(ENROLL_GUID)))
    ace = parse_security_descriptor(value)[0]
    assert ace.sid == "S-1-5-11" and ace.object_type == ENROLL_GUID and ace.kind == "allow"

def test_nested_group_effective_right_fixture():
    # Resolver expands user -> Group A -> Group B; the rights engine consumes Group B.
    value = descriptor(allow("S-1-5-21-1-2-3-2001"))
    aces = parse_security_descriptor(value)
    assert effective_enrollment(aces, {"S-1-5-21-1-2-3-2001"})

def test_explicit_deny_defeats_allow():
    aces = parse_security_descriptor(descriptor(deny("S-1-5-11"), allow("S-1-5-11")))
    assert not effective_enrollment(aces, {"S-1-5-11"})

def test_ldap_shaped_fixture_matrix():
    expected = {"A": True, "B": False, "C": False, "D": False, "E": False,
                "F": False, "G": False, "H": True, "I": True, "J": False}
    for scenario, want in expected.items():
        _, cas, templates = collect_fixture(scenario)
        assert len(cas) == 1 and len(templates) == 1
        published = templates[0].name in {n.rsplit(",", 1)[-1].removeprefix("CN=") for n in cas[0].templates}
        ctx = PrincipalContext(set(templates[0].evidence["low_privileged_subject_sids"]))
        ok, _ = classify_esc1(templates[0], cas[0], ctx, published)
        assert ok is want, scenario

def test_ldap_fixture_retains_raw_attributes_and_acl_evidence():
    _, _, templates = collect_fixture("A")
    t0 = templates[0]
    assert "nTSecurityDescriptor" in t0.evidence["raw_attributes"]
    assert t0.evidence["enrollment_ace_evidence"]

def test_object_and_right_mismatch_do_not_grant_enrollment():
    wrong = parse_security_descriptor(descriptor(allow("S-1-5-11", obj="11111111-1111-1111-1111-111111111111")))
    auto = parse_security_descriptor(descriptor(allow("S-1-5-11", obj="a05b8cc2-17bc-4802-a710-e7c15ab866a2")))
    assert not effective_enrollment(wrong, {"S-1-5-11"})
    assert not effective_enrollment(auto, {"S-1-5-11"})

def test_publication_index_handles_case_and_dangling_references():
    _, cas, templates = collect_fixture("A")
    cas.append(CA("OtherCA", "other", templates=["LAB-ESC1", "MissingTemplate"]))
    linked, dangling, duplicates = build_publication_index(cas, templates)
    assert [x.name for x in linked["Lab-ESC1"]] == ["LabCA", "OtherCA"]
    assert dangling == [("OtherCA", "MissingTemplate")]
    assert not duplicates

def test_acl_semantics_matrix():
    sid0 = "S-1-5-11"
    assert effective_enrollment(parse_security_descriptor(descriptor(allow(sid0), deny(sid0))), {sid0})
    assert not effective_enrollment(parse_security_descriptor(descriptor(deny(sid0), allow(sid0))), {sid0})
    assert effective_enrollment(parse_security_descriptor(descriptor(allow(sid0, mask=0x100 | 0x20))), {sid0})
    assert effective_enrollment(parse_security_descriptor(descriptor(allow(sid0, mask=0x10000000))), {sid0})
    inherit_only = parse_security_descriptor(descriptor(allow(sid0, flags=0x08)))
    assert not effective_enrollment(inherit_only, {sid0})

def test_malformed_descriptor_is_nonfatal():
    from ad_enum.security import parse_security_descriptor_safe
    aces, warnings = parse_security_descriptor_safe(b"\x01\x00")
    assert aces == [] and warnings

def test_genericwrite_and_autoenroll_are_not_enroll():
    sid0 = "S-1-5-11"
    assert not effective_enrollment(parse_security_descriptor(descriptor(allow(sid0, mask=0x40000000))), {sid0})
    assert not effective_enrollment(parse_security_descriptor(descriptor(allow(sid0, obj="a05b8cc2-17bc-4802-a710-e7c15ab866a2"))), {sid0})

def test_unknown_ace_type_is_never_a_grant():
    unknown = parse_security_descriptor(descriptor(allow("S-1-5-11", typ=9)))
    assert unknown[0].kind == "unknown"
    assert not effective_enrollment(unknown, {"S-1-5-11"})

@pytest.mark.parametrize("ekus,policies,want", [
    (["1.3.6.1.5.5.7.3.2"], [], True),       # Client Authentication
    (["1.3.6.1.4.1.311.20.2.2"], [], True),  # Smart Card Logon
    (["1.3.6.1.5.2.3.4"], [], True),         # PKINIT Client Authentication
    (["2.5.29.37.0"], [], True),             # Any Purpose
    ([], [], True),                           # no restriction
    (["1.3.6.1.5.5.7.3.1"], [], False),     # Server Authentication only
    (["1.3.6.1.5.5.7.3.3"], [], False),     # Code Signing only
    (["1.3.6.1.5.5.7.3.4"], [], False),     # EFS only
    (["1.3.6.1.2.3", "1.3.6.1.5.5.7.3.2"], [], True),
    (["1.3.6.1.5.5.7.3.1"], ["1.3.6.1.5.5.7.3.2"], True),
])
def test_authentication_eku_application_policy_matrix(ekus, policies, want):
    ok, _ = classify_esc1(t(ekus=ekus, application_policies=policies), CA0, P)
    assert ok is want
