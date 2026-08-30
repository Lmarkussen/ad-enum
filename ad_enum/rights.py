from .security import AUTOENROLL_GUID, ENROLL_GUID, TEMPLATE_CLASS_GUID, GENERIC_ALL, CONTROL_ACCESS, WRITE_DACL, WRITE_OWNER

GENERIC_WRITE = 0x40000000

def derive_template_rights(aces):
    enroll, auto, modify = {}, {}, {}
    for ace in aces:
        if ace.kind != "allow" or not ace.applies_to_object: continue
        if ace.applies_to(TEMPLATE_CLASS_GUID, ENROLL_GUID): enroll.setdefault(ace.sid, []).append(ace)
        if ace.applies_to(TEMPLATE_CLASS_GUID, AUTOENROLL_GUID):
            auto.setdefault(ace.sid, []).append(ace)
        if ace.mask & (GENERIC_ALL | GENERIC_WRITE | WRITE_DACL | WRITE_OWNER): modify.setdefault(ace.sid, []).append(ace)
    # An explicit deny for the same SID defeats an allow for that SID.
    for ace in aces:
        if ace.kind == "deny":
            enroll.pop(ace.sid, None); auto.pop(ace.sid, None)
    return enroll, auto, modify

def effective_enrollment(aces, candidate_sids):
    """Apply the ordered AD DACL algorithm to the enrollment extended right."""
    result = {}
    for sid in candidate_sids:
        granted = denied = False; evidence = []
        for ace in aces:
            if ace.sid != sid or not ace.applies_to(TEMPLATE_CLASS_GUID, ENROLL_GUID): continue
            if ace.kind == "deny" and not granted: denied = True; evidence.append(ace)
            elif ace.kind == "allow" and not denied: granted = True; evidence.append(ace)
        if granted and not denied: result[sid] = evidence
    return result
