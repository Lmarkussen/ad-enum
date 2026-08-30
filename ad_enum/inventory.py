"""Small normalized inventory shared by native and external collectors."""
from dataclasses import dataclass, field
import json
import base64
from pathlib import Path
import re
import socket
from .security import sid_from_bytes

def _identifier(value):
    if isinstance(value, list) and len(value) == 1:
        return _identifier(value[0])
    if isinstance(value, dict) and "base64" in value:
        try: return sid_from_bytes(base64.b64decode(value["base64"]))
        except Exception: return ""
    if isinstance(value, str) and not value.startswith("S-"):
        # Some ldap3/JSON paths expose binary objectSid as a latin-1 string.
        try: return sid_from_bytes(value.encode("latin1"))
        except Exception: return ""
    if isinstance(value, (bytes, bytearray)):
        try: return sid_from_bytes(value)
        except Exception: return ""
    return value

def _bloodhound_identifier(row, props):
    value = row.get("ObjectIdentifier") or props.get("objectsid") or props.get("objectid")
    # BloodHound qualifies well-known SIDs as DOMAIN-SID; the SID itself is
    # the stable identity and matches native LDAP/LDAPDomainDump.
    if isinstance(value, str) and "-S-" in value:
        value = value[value.index("S-"):]
    return value or props.get("distinguishedname") or props.get("name")

KINDS = ("domains", "users", "groups", "computers", "gmsa", "domain_controllers", "ous", "gpos", "relationships")

def _first(value, default=""):
    return value[0] if isinstance(value, list) and value else (value if value is not None else default)

def _attribute(attrs, *names):
    lowered = {str(key).lower(): value for key, value in attrs.items()}
    for name in names:
        if name.lower() in lowered: return _first(lowered[name.lower()])
    return ""

def build_targets(inventory, resolver=socket.getaddrinfo):
    """Create safe network targets from normalized AD computer records."""
    targets = []
    for record in inventory.records.get("computers", {}).values():
        a = record.attributes
        fqdn = _attribute(a, "dNSHostName", "dnshostname")
        name = _attribute(a, "name", "cn", "sAMAccountName")
        fqdn = fqdn or (name.rstrip("$") if name else "")
        ips, dns_status = [], "UNRESOLVED"
        try:
            ips = sorted({item[4][0] for item in resolver(fqdn, 445, type=socket.SOCK_STREAM)})
            dns_status = "RESOLVED" if ips else "UNRESOLVED"
        except (OSError, socket.gaierror):
            dns_status = "FAILED"
        targets.append({"identifier": record.identifier, "hostname": name.rstrip("$"),
                        "fqdn": fqdn, "ips": ips, "dns_status": dns_status,
                        "sid": record.identifier if str(record.identifier).upper().startswith("S-") else "",
                        "sources": record.sources, "attributes": a})
    return targets

def parse_netexec_smb(text):
    """Parse stable NetExec SMB table fields while retaining raw evidence."""
    results = []
    pattern = re.compile(r"SMB\s+(?P<ip>\S+)\s+(?P<name>\S+)\s+\S+\s+(?P<os>.+?)\s+\(name:(?P<host>[^)]+)\)\s+\(domain:(?P<domain>[^)]+)\)\s+\(signing:(?P<signing>[^)]+)\)(?:\s+\(SMBv1:(?P<smbv1>[^)]+)\))?")
    for line in text.splitlines():
        m = pattern.search(line)
        if m:
            d = m.groupdict(); d["smb_reachable"] = True
            d["smb_authenticated"] = "[+]" in line
            d["smb_signing"] = d.pop("signing").strip().lower() not in {"false", "none", "no"}
            d["smbv1"] = (d.pop("smbv1") or "unknown").strip()
            d["architecture"] = "x64" if " x64" in d["os"].lower() else "unknown"
            d["raw"] = line; results.append(d)
    for line in text.splitlines():
        match = re.search(r"SMB\s+(\S+).*\[\+\].*:", line)
        if match:
            for result in results:
                if result["ip"] == match.group(1): result["smb_authenticated"] = True
    return results

def sensitive_description(text):
    if isinstance(text, list): text = " ".join(str(x) for x in text)
    if not text: return False
    return bool(re.search(r"(?:password|passwd|pwd)\s*[:=]|(?:username|user)\s*[:=].+[/\\](?:password|passwd|pwd)\s*[:=]|\b(?:api[_ -]?key|token|secret)\s*[:=]", text, re.I))

@dataclass
class InventoryRecord:
    kind: str
    identifier: str
    attributes: dict = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)

@dataclass
class DomainInventory:
    records: dict[str, dict[str, InventoryRecord]] = field(default_factory=lambda: {k: {} for k in KINDS})
    password_policy: dict = field(default_factory=dict)
    diagnostics: list[str] = field(default_factory=list)

    def add(self, kind, identifier, attributes=None, source=""):
        if kind not in self.records: self.records[kind] = {}
        key = str(identifier or "").lower()
        if not key: return
        record = self.records[kind].get(key)
        if record is None:
            self.records[kind][key] = InventoryRecord(kind, str(identifier), attributes or {}, [source] if source else [])
        else:
            # Native LDAP may carry binary security descriptors.  Do not let
            # a later structured-source placeholder (or an empty value)
            # destroy that evidence during correlation.
            for name, value in (attributes or {}).items():
                old = record.attributes.get(name)
                if old not in (None, "", [], {}) and value in (None, "", [], {}):
                    continue
                if isinstance(old, (bytes, bytearray)) and isinstance(value, dict):
                    continue
                record.attributes[name] = value
            if source and source not in record.sources: record.sources.append(source)

    def counts(self): return {kind: len(values) for kind, values in self.records.items() if kind != "relationships"}

    def merge(self, other):
        for kind, records in other.records.items():
            for record in records.values(): self.add(kind, record.identifier, record.attributes, *(record.sources or [""]))
        if self.password_policy and other.password_policy and self.password_policy != other.password_policy:
            self.diagnostics.append("password policy differs between sources")
        elif other.password_policy: self.password_policy.update(other.password_policy)
        self.diagnostics.extend(other.diagnostics)
        return self

def _data(path):
    try: return json.loads(Path(path).read_text())
    except (OSError, ValueError): return None

def _bh_records(directory):
    inventory = DomainInventory()
    for path in Path(directory).glob("*.json"):
        data = _data(path)
        if not isinstance(data, dict): continue
        rows = data.get("data", [])
        if not isinstance(rows, list): continue
        name = path.name.lower()
        kind = next((k for k in ("users", "groups", "computers", "domains", "ous", "gpos", "trusts") if k in name), None)
        if not kind: continue
        if kind == "trusts": kind = "relationships"
        for row in rows:
            props = row.get("Properties", row) if isinstance(row, dict) else {}
            identifier = _bloodhound_identifier(row, props)
            inventory.add(kind, identifier, props, "bloodhound")
            if kind == "computers" and (row.get("IsDC") or props.get("isdc") or
                                         "DOMAIN CONTROLLERS" in str(props.get("name", "")).upper()):
                    inventory.add("domain_controllers", identifier, props, "bloodhound")
    return inventory

def parse_bloodhound(directory): return _bh_records(directory)

def parse_ldapdomaindump(directory):
    inventory = DomainInventory()
    for path in Path(directory).glob("*.json"):
        data = _data(path)
        rows = data if isinstance(data, list) else (data.get("entries", []) if isinstance(data, dict) else [])
        if not isinstance(rows, list): continue
        name = path.name.lower()
        kind = "users" if "user" in name else "groups" if "group" in name else "computers" if "computer" in name else None
        if "policy" in name:
            if rows and isinstance(rows[0], dict):
                attrs = rows[0].get("attributes", rows[0])
                inventory.password_policy = normalize_password_attributes(attrs, "ldapdomaindump")
            continue
        if not kind: continue
        for row in rows:
            if not isinstance(row, dict): continue
            attrs = row.get("attributes", row)
            attrs = {key: (value[0] if isinstance(value, list) and len(value) == 1 else value)
                     for key, value in attrs.items()}
            identifier = attrs.get("objectSid") or attrs.get("sAMAccountName") or attrs.get("distinguishedName") or row.get("dn")
            inventory.add(kind, identifier, attrs, "ldapdomaindump")
    return inventory

def native_inventory(raw):
    inventory = DomainInventory()
    root = raw.get("defaultNamingContext", "")
    inventory.add("domains", root, {"distinguishedName": root}, "native-ldap")
    for row in raw.get("identities", []):
        classes = {str(x).lower() for x in row.get("objectClass", [])}
        kind = ("gmsa" if "msds-groupmanagedserviceaccount" in classes else
                "groups" if "group" in classes else "computers" if "computer" in classes else "users")
        identifier = _identifier(row.get("objectSid")) or row.get("sAMAccountName") or row.get("distinguishedName")
        inventory.add(kind, identifier, row, "native-ldap")
        if kind == "computers":
            uac = row.get("userAccountControl", 0)
            primary_group = row.get("primaryGroupID", 0)
            if isinstance(uac, list): uac = uac[0] if uac else 0
            if isinstance(primary_group, list): primary_group = primary_group[0] if primary_group else 0
            spns = " ".join(str(x) for x in (row.get("servicePrincipalName") or []))
            dn = str(row.get("distinguishedName", ""))
            try: uac_value, group_value = int(uac or 0), int(primary_group or 0)
            except (TypeError, ValueError): uac_value, group_value = 0, 0
            if uac_value & 0x2000 or group_value == 516 or "OU=DOMAIN CONTROLLERS" in dn.upper() or "ldap/" in spns.lower():
                inventory.add("domain_controllers", identifier, {"evidence": "native LDAP DC indicators", **row}, "native-ldap")
        if kind == "gmsa":
            inventory.add("gmsa", identifier, {"gmsa": True, **row}, "native-ldap")
    inventory.password_policy = normalize_password_attributes(raw.get("passwordPolicy", {}), "native-ldap")
    return inventory

def normalize_password_policy(text, source="netexec"):
    result = {}
    patterns = {
        "minimum_password_length": r"Minimum password length:\s*(\d+)",
        "password_history_length": r"Password history length:\s*(\d+)",
        "maximum_password_age": r"Maximum password age:\s*(.+)",
        "minimum_password_age": r"Minimum password age:\s*(.+)",
        "lockout_threshold": r"Account lockout threshold:\s*(\d+)",
        "lockout_duration": r"(?:Account lockout duration|Locked Account Duration):\s*(.+)",
        "lockout_observation_window": r"(?:Lockout observation window|Reset Account Lockout Counter):\s*(.+)",
        "complexity_required": r"(?:Password complexity requirements|Password Complexity Flags):\s*(.+)",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, text, re.I)
        if match: result[key] = match.group(1).strip()
    return {"values": result, "canonical": canonical_policy_values(result), "source": source, "raw_excerpt": text[-4000:]}

def normalize_password_attributes(attrs, source="ldap-native"):
    """Normalize domain-DNS password fields without relying on text output."""
    keys = {
        "minPwdLength": "minimum_password_length", "pwdHistoryLength": "password_history_length",
        "maxPwdAge": "maximum_password_age", "minPwdAge": "minimum_password_age",
        "lockoutThreshold": "lockout_threshold", "lockOutObservationWindow": "lockout_observation_window",
        "lockoutDuration": "lockout_duration", "pwdProperties": "complexity_required",
    }
    values = {}
    for key, normalized in keys.items():
        if key in attrs:
            value = attrs[key]
            values[normalized] = value[0] if isinstance(value, list) and len(value) == 1 else value
    return {"values": values, "canonical": canonical_policy_values(values), "source": source}

def _duration_seconds(value):
    if isinstance(value, (int, float)): return int(abs(value))
    text = str(value).lower()
    total = 0
    for number, unit in re.findall(r"(\d+)\s*(day|hour|minute|second)", text):
        total += int(number) * {"day": 86400, "hour": 3600, "minute": 60, "second": 1}[unit]
    return total if total else None

def canonical_policy_values(values):
    result = {}
    for key, value in values.items():
        if key in {"maximum_password_age", "minimum_password_age", "lockout_duration", "lockout_observation_window"}:
            parsed = _duration_seconds(value)
            if parsed is not None: result[key + "_seconds"] = parsed
        elif key == "complexity_required":
            result["complexity_enabled"] = str(value).strip() not in {"0", "000000", "false", "disabled"}
        elif key in {"minimum_password_length", "password_history_length", "lockout_threshold"}:
            try: result[key] = int(value)
            except (TypeError, ValueError): result[key] = value
    return result
