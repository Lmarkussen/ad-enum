"""Native parser for Windows self-relative security descriptors and ACLs."""
import struct
from dataclasses import dataclass
from uuid import UUID

ENROLL_GUID = UUID("0e10c968-78fb-11d2-90d4-00c04f79dc55")
AUTOENROLL_GUID = UUID("a05b8cc2-17bc-4802-a710-e7c15ab866a2")
CONTROL_ACCESS = 0x100
GENERIC_ALL = 0x10000000
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000
TEMPLATE_CLASS_GUID = UUID("e5209ca2-3bba-11d2-90cc-00c04fd91ab1")

@dataclass
class ACE:
    ace_type: int
    kind: str
    sid: str
    mask: int
    object_type: UUID | None = None
    inherited_object_type: UUID | None = None
    flags: int = 0
    applies_to_object: bool = True
    raw: bytes = b""

    @property
    def inherited(self): return bool(self.flags & 0x10)

    def permits(self, right_guid):
        return bool(self.mask & GENERIC_ALL) or (bool(self.mask & CONTROL_ACCESS) and
               (self.object_type is None or self.object_type == right_guid))

    def applies_to(self, object_class_guid, right_guid):
        if not self.applies_to_object or not self.permits(right_guid): return False
        return self.inherited_object_type is None or self.inherited_object_type == object_class_guid

def sid_from_bytes(data, offset=0):
    rev, count = data[offset], data[offset + 1]
    authority = int.from_bytes(data[offset+2:offset+8], "big")
    subs = [struct.unpack_from("<I", data, offset+8+i*4)[0] for i in range(count)]
    return "S-" + "-".join([str(rev), str(authority), *map(str, subs)])

def _guid(data, offset):
    return UUID(bytes_le=data[offset:offset+16])

def parse_acl(data, offset):
    if not offset: return []
    _, _, _, count, _ = struct.unpack_from("<BBHHH", data, offset)
    pos, result = offset + 8, []
    for _ in range(count):
        typ, flags, size = struct.unpack_from("<BBH", data, pos)
        raw = data[pos:pos+size]
        mask = struct.unpack_from("<I", data, pos+4)[0]
        object_type = inherited_type = None
        sid_offset = pos + 8
        if typ in (5, 6):
            oflags = struct.unpack_from("<I", data, pos+8)[0]
            cursor = pos + 12
            if oflags & 1: object_type, cursor = _guid(data, cursor), cursor + 16
            if oflags & 2: inherited_type, cursor = _guid(data, cursor), cursor + 16
            sid_offset = cursor
        kind = "allow" if typ in (0, 5) else "deny" if typ in (1, 6) else "unknown"
        result.append(ACE(typ, kind, sid_from_bytes(data, sid_offset), mask,
                          object_type, inherited_type, flags, not bool(flags & 0x08), raw))
        pos += size
    return result

def parse_security_descriptor(data):
    if not data: return []
    if isinstance(data, str): data = data.encode("latin1")
    _, _, _, _, _, _, dacl = struct.unpack_from("<BBHIIII", data, 0)
    return parse_acl(data, dacl)

def parse_security_descriptor_safe(data):
    try:
        return parse_security_descriptor(data), []
    except (IndexError, struct.error, ValueError, TypeError) as exc:
        return [], [f"malformed security descriptor: {exc}"]
