"""AD CS vulnerability rules; no LDAP dependencies belong in this module."""

ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
CLIENT_AUTH_EKU = {
    "1.3.6.1.5.5.7.3.2",  # Client Authentication
    "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
    "1.3.6.1.5.2.3.4",  # PKINIT Client Authentication
    "2.5.29.37.0",        # Any Purpose
}


def evaluate_esc1(template, ca, principals, published=True):
    reasons = []
    supplies = bool(template.name_flags & ENROLLEE_SUPPLIES_SUBJECT)
    policies = set(getattr(template, "application_policies", []))
    auth_oids = set(template.ekus) | policies
    auth = bool(auth_oids & CLIENT_AUTH_EKU) or not auth_oids
    low_enrollable = bool(template.enroll_sids & principals.low_privileged_sids)
    if not published: reasons.append("template is not published by this Enterprise CA")
    if not supplies:
        reasons.append("enrollee cannot supply the subject/SAN")
    if not auth:
        reasons.append("template has no client-authentication-capable EKU")
    if not low_enrollable:
        reasons.append("no low-privileged principal has effective enrollment rights")
    if template.manager_approval or (template.enrollment_flags & CT_FLAG_PEND_ALL_REQUESTS):
        reasons.append("manager approval is required")
    if template.authorized_signatures:
        reasons.append(f"authorized signatures required: {template.authorized_signatures}")
    vulnerable = not reasons
    if vulnerable:
        reasons.append("subject/SAN supply, authentication EKU, low-privilege enrollment, and no approval/signature gate")
    evidence = __import__("ad_enum.models", fromlist=["ESC1Evidence"]).ESC1Evidence(
        published_by=[ca.name] if published else [], subject_supply=supplies,
        authentication_policy=sorted(auth_oids), manager_approval=template.manager_approval,
        authorized_signatures=template.authorized_signatures,
        effective_enrollers={s: template.enrollment_evidence.get(s, []) for s in template.enroll_sids},
        acl_evidence={"aces": template.security_descriptor},
        group_membership_evidence=template.evidence.get("group_membership", {}),
        raw_template_flags={"name": template.name_flags, "enrollment": template.enrollment_flags},
        reasons=reasons, vulnerable=vulnerable)
    return vulnerable, reasons, evidence

def classify_esc1(template, ca, principals, published=True):
    vulnerable, reasons, _ = evaluate_esc1(template, ca, principals, published)
    return vulnerable, reasons
