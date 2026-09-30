"""Read-only SCCM/MECM infrastructure inventory and correlation."""
import re
import ipaddress
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from ad_enum.sccm_models import (normalize_pxe_evidence, normalize_sccm_topology,
                                 normalize_sql_relationship)


def _values(attrs, key):
    value = attrs.get(key, [])
    return value if isinstance(value, list) else ([value] if value not in (None, "") else [])


def parse_sccm_publication(objects):
    """Normalize only SCCM-specific publication evidence; no hostname guesses."""
    result = {"objects": [], "site_codes": [], "roles": [], "endpoints": []}
    for obj in objects or []:
        if not isinstance(obj, dict):
            continue
        attrs = {str(k).lower(): v for k, v in obj.items()}
        cn = str((_values(attrs, "cn") or _values(attrs, "name") or [""])[0])
        classes = {str(v).lower() for v in _values(attrs, "objectclass")}
        values = [cn]
        for key in ("keywords", "mssms-assignment-site-code", "mssms-site-code"):
            values.extend(str(v) for v in _values(attrs, key))
        # SCCM object names encode the site code as SMS-Site-<code> and
        # SMS-MP-<code>-<host>. Do not mistake the literal ``SMS`` prefix
        # for a site code; arbitrary keyword values are only secondary
        # evidence and are filtered the same way.
        encoded = re.findall(r"SMS-(?:SITE|MP)-([A-Z][A-Z0-9]{2})(?:-|$)", cn, re.I)
        candidates = encoded or [m for value in values[1:]
                                 for m in re.findall(r"\b[A-Z][A-Z0-9]{2}\b", value)]
        site_codes = sorted({m.upper() for m in candidates if m.upper() != "SMS"})
        for code in site_codes:
            if code not in result["site_codes"]: result["site_codes"].append(code)
        roles = [str(v) for v in _values(attrs, "mssms-site-system-roles")]
        if "mssmssite" in classes:
            roles.append("site")
        if "mssmsmanagementpoint" in classes:
            roles.append("management-point")
        if "serviceadministrationpoint" in classes or "intellimirrorscp" in classes:
            roles.append("service-administration-point")
        bindings = [str(v) for v in _values(attrs, "servicebindinginformation")]
        dns = [str(v) for v in (_values(attrs, "servicednsname") + _values(attrs, "dnshostname"))]
        item = {"dn": obj.get("distinguishedName", ""), "cn": cn,
                "object_class": _values(attrs, "objectclass"),
                "site_codes": site_codes, "roles": roles, "service_dns_names": dns,
                "service_bindings": bindings, "raw": obj}
        result["objects"].append(item)
        result["roles"].extend(roles)
        result["endpoints"].extend({"host": host, "source": obj.get("distinguishedName", ""),
                                     "site_code": site_codes[0] if len(site_codes) == 1 else None,
                                     "roles": sorted(set(roles))}
                                    for host in dns if host)
    result["roles"] = sorted(set(result["roles"]))
    endpoint_map = {(item["host"].lower(), item["source"].lower()): item
                    for item in result["endpoints"]}
    result["endpoints"] = sorted(endpoint_map.values(),
                                  key=lambda x: (x["host"], x["source"]))
    result["site_codes"] = sorted(set(result["site_codes"]))
    return result

def discover(inventory, raw=None, dns_map=None):
    dns_records = {str(x.get("fqdn", "")).lower(): x for x in (dns_map or {}).get("records", [])}
    hosts = []
    relationships = []
    spn_accounts = []
    for record in inventory.records.get("computers", {}).values():
        attrs = record.attributes
        name = str(attrs.get("name") or attrs.get("cn") or "").rstrip("$")
        spns = attrs.get("servicePrincipalName") or attrs.get("serviceprincipalnames") or []
        if isinstance(spns, str): spns = [spns]
        if spns:
            spn_accounts.append({"account": attrs.get("sAMAccountName", name),
                                 "spns": list(spns), "sources": record.sources})
        hints = []
        if any("MSSQLSvc/" in str(x) for x in spns): hints.append("SQL")
        if any(str(x).upper().startswith(("HTTP/", "WSUS/")) for x in spns): hints.append("management-point-candidate")
        if "MECM" in name.upper() or "SCCM" in name.upper(): hints.append("SCCM-host-candidate")
        if "SQL" in name.upper() or any("MSSQLSvc/" in str(x) for x in spns): hints.append("SQL")
        if hints:
            role = "candidate"
            upper = {x.upper() for x in hints}
            if "SQL" in upper and "SCCM-HOST-CANDIDATE" not in upper: role = "sql-candidate"
            elif "MANAGEMENT-POINT-CANDIDATE" in upper: role = "management-point-candidate"
            elif "SCCM-HOST-CANDIDATE" in upper: role = "site-server-candidate"
            hosts.append({"name": name, "fqdn": attrs.get("dNSHostName", ""),
                          "sid": record.identifier, "role": role,
                          "hints": sorted(set(hints)), "sources": record.sources})
            for hint in sorted(set(hints)):
                relationships.append({"host": name, "role": hint, "confidence": "candidate",
                                      "evidence": {"hints": sorted(set(hints)), "spns": list(spns)}})
    publication = parse_sccm_publication((raw or {}).get("sccm", []))
    site_code = publication["site_codes"][0] if len(publication["site_codes"]) == 1 else None
    management_points = []
    for item in publication["objects"]:
        item_roles = {role.lower() for role in item["roles"]}
        if "management-point" not in item_roles:
            continue
        for endpoint in publication["endpoints"]:
            if endpoint["source"] != item["dn"]:
                continue
            address = dns_records.get(endpoint["host"].lower(), {})
            management_points.append({"host": endpoint["host"], "fqdn": endpoint["host"],
                                      "ip_addresses": address.get("ip_addresses", []),
                                      "site_code": endpoint.get("site_code") or site_code,
                                      "protocol": "unknown", "port": None,
                                      "confidence": "confirmed", "evidence": item["dn"]})
    for endpoint in publication["endpoints"]:
        for host in hosts:
            if endpoint["host"].lower() in {host["name"].lower(), host["fqdn"].lower()}:
                host.setdefault("sccm_evidence", []).append(endpoint)
                host["role"] = "confirmed-sccm-published-host"
                host["confidence"] = "sccm-publication"
    pxe = {"status": "UNKNOWN", "implementation": "unknown", "evidence": []}
    for item in publication["objects"]:
        attrs = {str(k).lower(): v for k, v in item.get("raw", {}).items()}
        netboot = [v for key in ("netbootscpbl", "netbootanswer", "netbootscp")
                   for v in _values(attrs, key) if v not in (None, "", [])]
        if netboot:
            pxe = {"status": "ENABLED", "implementation": "unknown",
                   "evidence": [{"dn": item["dn"], "attributes": ["netbootSCPBL", "netbootAnswer", "netbootSCP"]}]}
            break
    for host in hosts:
        address = dns_records.get(str(host.get("fqdn", "")).lower())
        if address: host["ip_addresses"] = address.get("ip_addresses", [])
    topology_nodes = [{"host": x.get("fqdn") or x.get("name"),
                       "ip": (x.get("ip_addresses") or [""])[0],
                       "role": x.get("role", "candidate"), "site": site_code or "",
                       "status": "CANDIDATE", "confidence": x.get("confidence", "CANDIDATE"),
                       "low_priv_visibility": "DETECTED", "sources": x.get("sources", []),
                       "evidence": x.get("hints", [])} for x in hosts]
    topology_nodes.extend({"host": x.get("fqdn") or x.get("host"),
                           "ip": (x.get("ip_addresses") or [""])[0],
                           "role": "management-point", "site": x.get("site_code") or site_code or "",
                           "status": "CONFIRMED", "confidence": "CONFIRMED",
                           "low_priv_visibility": "DETECTED", "sources": ["SCCM LDAP publication"],
                           "evidence": [x.get("evidence", "")]} for x in management_points)
    topology = normalize_sccm_topology({"site_code": site_code or "", "nodes": topology_nodes,
                                        "relationships": relationships, "sources": ["SCCM LDAP publication"]})
    return {"hosts": hosts, "relationships": relationships, "topology": topology,
            "spn_accounts": spn_accounts,
            "publication": publication,
            "site_code": site_code, "site_code_sources": [x["dn"] for x in publication["objects"]
                            if site_code and site_code in x["site_codes"]],
            "management_points": management_points, "distribution_points": [],
            "site_servers": [], "sms_providers": [], "sql_servers": [x for x in hosts if x["role"] == "sql-candidate"],
            "pxe": normalize_pxe_evidence(pxe),
            "dp_content": [], "task_sequences": [],
            "sql_relationship": normalize_sql_relationship({"site_code": site_code or "",
                                                               "status": "NOT TESTED"}),
            "sup_wsus": [], "status": "sccm-publication-and-inventory"}


def probe_management_points(management_points, timeout=5):
    """Probe only the two documented, read-only MP metadata endpoints.

    The response is parsed into bounded metadata; certificate/key material in
    MPKEYINFORMATION is deliberately never retained.
    """
    results = []
    paths = ("/SMS_MP/.sms_aut?MPLIST", "/SMS_MP/.sms_aut?MPKEYINFORMATION")
    for mp in management_points or []:
        host = mp.get("fqdn") or mp.get("host")
        if not host:
            continue
        for scheme in ("http", "https"):
            for path in paths:
                item = {"host": host, "scheme": scheme, "port": 443 if scheme == "https" else 80,
                        "path": path, "status": "FAILED", "sccm_marker": False}
                try:
                    request = urllib.request.Request(f"{scheme}://{host}{path}",
                                                     headers={"User-Agent": "AD-Enum/1 SCCM inventory"})
                    with urllib.request.urlopen(request, timeout=timeout) as response:
                        body = response.read(16384)
                        item["http_status"] = response.status
                        root = ET.fromstring(body)
                        root_name = root.tag.rsplit("}", 1)[-1].upper()
                        item["sccm_marker"] = root_name in {"MPLIST", "MPKEYINFORMATION"}
                        item["status"] = "CONFIRMED" if item["sccm_marker"] else "RESPONDED"
                        if root_name == "MPLIST":
                            mp_node = next((x for x in root.iter() if x.tag.rsplit("}", 1)[-1].upper() == "MP"), None)
                            if mp_node is not None:
                                item["metadata"] = {key.lower(): value for key, value in mp_node.attrib.items()
                                                     if key.lower() in {"name", "fqdn", "version"}}
                                item["ssl_state"] = next((x.attrib.get("Value") for x in root.iter()
                                                           if x.attrib.get("Name") == "SSLState"), None)
                        elif root_name == "MPKEYINFORMATION":
                            item["metadata"] = {name: next((x.text for x in root.iter()
                                                             if x.tag.rsplit("}", 1)[-1].upper() == name), None)
                                                 for name in ("SITECODE", "ASSIGNMENTSITECODE", "MACHINENAME", "FQDN")}
                except (urllib.error.URLError, TimeoutError, OSError, ET.ParseError) as exc:
                    item["error"] = type(exc).__name__
                    # Keep a bounded diagnostic for TLS/DNS troubleshooting,
                    # while never retaining response bodies or credentials.
                    if isinstance(exc, urllib.error.URLError):
                        item["error_detail"] = str(exc.reason)[:240]
                results.append(item)
    return results


def _candidate_ipv4(addresses):
    for address in addresses or []:
        try:
            if ipaddress.ip_address(str(address)).version == 4:
                return str(address)
        except ValueError:
            continue
    return ""


def _resolved_hostnames(dns_map):
    """Map lowercase FQDN/short names to a known IPv4 address."""
    index = {}
    for record in (dns_map or {}).get("records", []) or []:
        if not isinstance(record, dict):
            continue
        addresses = record.get("ip_addresses") or record.get("ips") or []
        if isinstance(addresses, str):
            addresses = [addresses]
        address = _candidate_ipv4(addresses)
        name = str(record.get("fqdn") or record.get("host") or "").strip().lower()
        if not address or not name:
            continue
        index.setdefault(name, address)
        index.setdefault(name.split(".")[0], address)
    return index


def pxe_candidates(result, host_identities=None):
    """Return deterministic PXE/DP candidates from SCCM discovery.

    SCCM commonly co-locates the management point, distribution point, and
    PXE/WDS role on a single site system, and the passive netboot SCP
    attributes are not always published.  Candidates are therefore drawn from
    discovered distribution points first and then from confirmed management
    points, each tagged with the discovery basis; arbitrary hosts are never
    invented or scanned.  Entries that canonicalize to the same endpoint
    (IPv4 address, or hostname resolved against the scan's own DNS map) are
    collapsed to a single candidate; genuinely distinct endpoints are kept.
    """
    result = result if isinstance(result, dict) else {}
    observed = [(item, "distribution-point") for item in (result.get("distribution_points", []) or [])]
    observed += [(item, "management-point") for item in (result.get("management_points", []) or [])]
    pxe_state = str((result.get("pxe") or {}).get("status", "")).upper()
    resolved = _resolved_hostnames(host_identities)
    candidates, seen = [], set()
    for item, basis in observed:
        if not isinstance(item, dict):
            continue
        host = str(item.get("fqdn") or item.get("host") or item.get("name") or "").strip()
        addresses = item.get("ip_addresses") or item.get("ips") or []
        if isinstance(addresses, str):
            addresses = [addresses]
        name_key = host.lower()
        address = (_candidate_ipv4(addresses) or resolved.get(name_key)
                   or resolved.get(name_key.split(".")[0], "") or "")
        target = address or host
        canonical = (address or name_key).casefold()
        if not canonical or canonical in seen:
            continue
        seen.add(canonical)
        candidates.append({"dp": str(target), "host": str(host or target),
                           "site_code": item.get("site_code", ""), "basis": basis,
                           "pxe_evidence": pxe_state == "ENABLED"})
    return sorted(candidates, key=lambda c: (c["site_code"], c["dp"].casefold()))


def _sccm_host(value):
    if isinstance(value, dict):
        value = value.get("fqdn") or value.get("host") or value.get("name")
    return str(value or "").strip().casefold()


def merge_sccmhunter(result, hunter):
    """Merge SCCMHunter ``find`` results into the native SCCM topology.

    Hosts already known from native LDAP keep their evidence and gain
    ``SCCMHunter`` in their source list; hosts only SCCMHunter observed are
    added with truthful SCCMHunter-only attribution.  Neither source is
    overwritten, so a disagreement between them remains visible.
    """
    result = result if isinstance(result, dict) else {}
    if not isinstance(hunter, dict) or str(hunter.get("status", "")).upper() != "PASS":
        return result

    def note_source(entry):
        sources = entry.setdefault("sources", [])
        # Entries that already existed came from native discovery.
        if not sources:
            sources.append("Native AD-Enum")
        if "SCCMHunter" not in sources:
            sources.append("SCCMHunter")

    default_site = (result.get("site_code")
                    or next(iter(hunter.get("site_codes") or []), ""))
    for role, additions, defaults in (
            ("management_points", hunter.get("management_points"), {}),
            ("site_servers", hunter.get("site_servers"), {}),
            ("distribution_points", hunter.get("distribution_points"), {"pxe": "ENABLED"})):
        entries = result.setdefault(role, [])
        by_host = {_sccm_host(item): item for item in entries if _sccm_host(item)}
        for addition in additions or []:
            host = _sccm_host(addition)
            if not host:
                continue
            existing = by_host.get(host)
            if existing is not None:
                note_source(existing)
                for key, value in defaults.items():
                    existing.setdefault(key, value)
                continue
            entry = {"host": host, "fqdn": host, "ip_addresses": [],
                     "site_code": addition.get("site_code") or default_site,
                     "confidence": "sccmhunter", "sources": ["SCCMHunter"],
                     "evidence": "SCCMHunter find"}
            entry.update(defaults)
            entries.append(entry)
            by_host[host] = entry

    if hunter.get("site_codes") and not result.get("site_code"):
        result["site_code"] = hunter["site_codes"][0]

    pxe = result.get("pxe") if isinstance(result.get("pxe"), dict) else {}
    if hunter.get("distribution_points"):
        if str(pxe.get("status", "UNKNOWN")).upper() != "ENABLED":
            pxe.update({"status": "ENABLED", "state": "ENABLED",
                        "implementation": pxe.get("implementation", "unknown")})
        pxe.setdefault("evidence", []).append(
            {"source": "SCCMHunter", "attribute": "netbootServer",
             "hosts": sorted({item["host"] for item in hunter["distribution_points"]})})
        sources = pxe.setdefault("sources", [])
        if "SCCMHunter" not in sources:
            sources.append("SCCMHunter")
        result["pxe"] = pxe
    return result


def normalize_relayking(data):
    """Keep RelayKing's structured exposure/path results without executing them."""
    if not isinstance(data, dict):
        return {"status": "UNAVAILABLE", "targets": [], "paths": [], "statistics": {}}
    paths = data.get("relay_paths", [])
    normalized = []
    for path in paths if isinstance(paths, list) else []:
        if not isinstance(path, dict):
            continue
        normalized.append({key: path.get(key) for key in
                           ("source_host", "source_ip", "source_protocol", "dest_host",
                            "dest_ip", "dest_protocol", "impact", "description",
                            "ntlmv1_required")})
    return {"status": "PASS", "targets": data.get("targets", []),
            "paths": normalized, "statistics": data.get("statistics", {}),
            "high_value_targets": data.get("high_value_targets", [])}
