from collections import deque

WELL_KNOWN = {
    "S-1-1-0": "Everyone", "S-1-5-11": "Authenticated Users",
    "S-1-5-32-544": "Builtin Administrators", "S-1-5-21-*-513": "Domain Users",
    "S-1-5-21-*-515": "Domain Computers", "S-1-5-21-*-512": "Domain Admins",
    "S-1-5-21-*-519": "Enterprise Admins",
}

class Resolver:
    def __init__(self, conn, base):
        self.conn, self.base, self.cache = conn, base, {}
        self.sid_to_name = {"S-1-1-0": "Everyone", "S-1-5-11": "Authenticated Users",
                            "S-1-5-32-544": "Builtin Administrators"}; self.sid_to_dn = {}; self.group_members = {}
        self.domain_sid = None

    def load(self):
        self.conn.search(self.base, "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
                         attributes=["objectSid", "sAMAccountName", "memberOf", "member"])
        for e in self.conn.entries:
            d = e.entry_attributes_as_dict; sid = str((d.get("objectSid") or [""])[0])
            name = str((d.get("sAMAccountName") or [e.entry_dn])[0]); self.sid_to_name[sid] = name
            self.sid_to_dn[sid] = e.entry_dn
            self.group_members[e.entry_dn.lower()] = [str(x).lower() for x in d.get("member", [])]
            if sid.startswith("S-") and sid.count("-") >= 4 and sid.rsplit("-", 1)[-1] in {"512", "513", "515", "519"}:
                self.domain_sid = sid.rsplit("-", 1)[0]
        if self.domain_sid:
            for rid, name in ((513,"Domain Users"),(515,"Domain Computers"),(512,"Domain Admins"),(519,"Enterprise Admins")):
                self.sid_to_name[f"{self.domain_sid}-{rid}"] = name

    def expand_groups(self, sid):
        if sid in self.cache: return self.cache[sid]
        seen, result, q = {sid}, {sid}, deque([sid])
        while q:
            current = q.popleft()
            dn = self.sid_to_dn.get(current, "").lower()
            for group_dn, members in self.group_members.items():
                if dn not in members: continue
                parent = next((s for s, d in self.sid_to_dn.items() if d.lower() == group_dn), "")
                if parent and parent not in seen: seen.add(parent); result.add(parent); q.append(parent)
        self.cache[sid] = result; return result
