"""Stable hostname/IP identity mapping shared by network-facing modules."""
import ipaddress
import re
import socket


def _ips(values):
    result = []
    for value in values or []:
        try:
            address = ipaddress.ip_address(str(value))
            if not address.is_multicast and not address.is_loopback and str(address) not in result:
                result.append(str(address))
        except ValueError:
            continue
    return result


def _record(records, fqdn, source, ips=(), **metadata):
    fqdn = str(fqdn or "").strip().rstrip(".").lower()
    if not fqdn or re.fullmatch(r"\d+(?:\.\d+){3}", fqdn):
        return
    key = fqdn
    item = records.setdefault(key, {"fqdn": fqdn, "short_name": fqdn.split(".", 1)[0],
                                   "ip_addresses": [], "ipv4_addresses": [], "ipv6_addresses": [],
                                   "sources": [], "resolution_methods": [], "conflicts": []})
    for ip in _ips(ips):
        if ip not in item["ip_addresses"]: item["ip_addresses"].append(ip)
        bucket = "ipv6_addresses" if ":" in ip else "ipv4_addresses"
        if ip not in item[bucket]: item[bucket].append(ip)
    if source and source not in item["sources"]: item["sources"].append(source)
    method = metadata.pop("resolution_method", "")
    if method and method not in item["resolution_methods"]: item["resolution_methods"].append(method)
    for key, value in metadata.items():
        if value not in (None, "", [], {}) and key not in item: item[key] = value


def build_dns_map(inventory, networkhound=None, resolver=socket.getaddrinfo):
    records = {}
    for record in inventory.records.get("computers", {}).values():
        attrs = record.attributes
        fqdn = attrs.get("dNSHostName") or attrs.get("dnshostname") or attrs.get("name") or attrs.get("cn")
        if isinstance(fqdn, list): fqdn = fqdn[0] if fqdn else ""
        if not fqdn: continue
        ips = []
        try: ips = [x[4][0] for x in resolver(str(fqdn), 0, type=socket.SOCK_STREAM)]
        except (OSError, socket.gaierror): pass
        _record(records, fqdn, "native-ldap", ips, resolution_method="native-dns",
                object_sid=record.identifier if str(record.identifier).upper().startswith("S-") else "",
                distinguished_name=attrs.get("distinguishedName", ""))
    for record in inventory.records.get("observed_hosts", {}).values():
        attrs = record.attributes
        _record(records, attrs.get("host") or attrs.get("hostname") or attrs.get("name"),
                "netexec", [attrs.get("ip")] if attrs.get("ip") else [], resolution_method="netexec")
    for item in (networkhound or {}).get("records", []):
        sid = item.get("object_sid", "")
        target = next((x for x in records.values() if sid and x.get("object_sid") == sid), None)
        if target is not None:
            for ip in _ips(item.get("ip_addresses") or item.get("ips", [])):
                if ip not in target["ip_addresses"]: target["ip_addresses"].append(ip)
                bucket = "ipv6_addresses" if ":" in ip else "ipv4_addresses"
                if ip not in target[bucket]: target[bucket].append(ip)
            if "networkhound" not in target["sources"]: target["sources"].append("networkhound")
            if "networkhound" not in target["resolution_methods"]: target["resolution_methods"].append("networkhound")
            if item.get("ad_site"): target["ad_site"] = item["ad_site"]
            if item.get("subnet"): target["subnet"] = item["subnet"]
        else:
            _record(records, item.get("fqdn") or item.get("hostname"), "networkhound",
                    item.get("ip_addresses") or item.get("ips", []), resolution_method="networkhound",
                    ad_site=item.get("ad_site"), subnet=item.get("subnet"), object_sid=sid,
                    distinguished_name=item.get("distinguished_name", ""))
    for item in records.values():
        item["ip_addresses"].sort(); item["ipv4_addresses"].sort(); item["ipv6_addresses"].sort()
        if len(item["ip_addresses"]) > 1:
            item["conflicts"].append({"type": "multiple-addresses", "values": item["ip_addresses"]})
    return {"schema_version": "1.0", "records": sorted(records.values(), key=lambda x: x["fqdn"]),
            "reverse": {ip: sorted({x["fqdn"] for x in records.values() if ip in x["ip_addresses"]})
                        for ip in sorted({ip for x in records.values() for ip in x["ip_addresses"]})}}


def parse_networkhound(data):
    """Accept NetworkHound's OpenGraph JSON without depending on its classes."""
    records = []
    if not isinstance(data, dict): return {"records": records, "raw_supported": False}
    graph = data.get("graph", data)
    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    node_map = {str(node.get("id")): node for node in nodes if isinstance(node, dict)}
    subnet_map = {str(node.get("id")): node.get("properties", {}).get("subnet")
                  for node in nodes if isinstance(node, dict) and "Subnet" in node.get("kinds", [])}
    located = {}
    for edge in graph.get("edges", []) if isinstance(graph, dict) else []:
        if edge.get("kind") != "LocatedIn": continue
        start = edge.get("start", {}).get("value"); end = edge.get("end", {}).get("value")
        if start in node_map and end in subnet_map: located[start] = subnet_map[end]
    for node in nodes if isinstance(nodes, list) else []:
        props = node.get("properties", node.get("Properties", node)) if isinstance(node, dict) else {}
        fqdn = props.get("dns_hostname") or props.get("fqdn") or props.get("name")
        ips = props.get("ip_addresses") or props.get("ip_address") or []
        if isinstance(ips, str): ips = [x.strip() for x in ips.split(";") if x.strip()]
        if ips and (fqdn or "Computer" in node.get("kinds", [])):
            records.append({"fqdn": fqdn, "ip_addresses": ips,
                            "object_sid": props.get("sid", "") or node.get("id", ""),
                            "ad_site": props.get("site"), "subnet": props.get("subnet") or located.get(str(node.get("id")))})
    return {"records": records, "sites": [node.get("properties", {}) for node in nodes if "Site" in node.get("kinds", [])],
            "subnets": [node.get("properties", {}) for node in nodes if "Subnet" in node.get("kinds", [])],
            "raw_supported": True}
