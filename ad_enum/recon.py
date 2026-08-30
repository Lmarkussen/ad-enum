"""Bounded, read-only models for secondary domain reconnaissance families."""
from collections import defaultdict, deque
import re


def normalize_mssql(inventory, *, sccm_relationship=None):
    """Build SQL instance candidates from observed SPNs and host records."""
    result = {}
    for record in inventory.records.get("computers", {}).values():
        attrs = record.attributes
        host = attrs.get("dNSHostName") or attrs.get("name") or attrs.get("cn") or record.identifier
        spns = attrs.get("servicePrincipalName") or []
        if isinstance(spns, str):
            spns = [spns]
        for spn in spns:
            match = re.match(r"MSSQLSvc/([^:]+)(?::(\d+))?", str(spn), re.I)
            if not match:
                continue
            instance_host, port = match.groups()
            key = (instance_host.lower(), port or "")
            item = result.setdefault(key, {"hostname": instance_host, "ip": "", "instance": "",
                                            "port": int(port) if port else None, "spns": [],
                                            "account": attrs.get("sAMAccountName", ""),
                                            "sources": set(), "confidence": "CANDIDATE"})
            item["spns"].append(str(spn)); item["sources"].update(record.sources)
            item["confidence"] = "CORROBORATED" if len(item["sources"]) > 1 else "CANDIDATE"
    output = []
    for item in result.values():
        item["sources"] = sorted(item["sources"])
        if sccm_relationship and item["hostname"].lower() == str(sccm_relationship.get("host", "")).lower():
            item["sccm"] = {"site_code": sccm_relationship.get("site_code", ""),
                            "database": sccm_relationship.get("database", ""),
                            "confidence": sccm_relationship.get("confidence", "UNKNOWN")}
        output.append(item)
    return sorted(output, key=lambda x: (x["hostname"].lower(), x["port"] or 0))


def normalize_dfs(rows):
    """Normalize published DFS namespaces/links without crawling targets."""
    result = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        targets = row.get("targets", row.get("target_uncs", []))
        if isinstance(targets, str): targets = [targets]
        result.append({"namespace": row.get("namespace", row.get("root", "")),
                       "path": row.get("path", row.get("link", "")),
                       "targets": sorted({str(x) for x in (targets or []) if x}),
                       "source": row.get("source", "native-ldap"),
                       "access": str(row.get("access", "UNKNOWN")).upper()})
    return result


def normalize_services(hosts):
    """Normalize only service observations already collected for known hosts."""
    output = []
    seen = set()
    for host in hosts or []:
        if not isinstance(host, dict): continue
        name = host.get("host") or host.get("hostname") or host.get("name") or host.get("ip", "")
        services = host.get("services", [])
        if isinstance(services, dict): services = [{"name": key, **(value if isinstance(value, dict) else {"state": value})}
                                                    for key, value in services.items()]
        for service in services or []:
            if isinstance(service, str): service = {"name": service}
            if not isinstance(service, dict): continue
            item = {"host": name, "ip": host.get("ip", ""), "name": service.get("name", ""),
                    "port": service.get("port"), "transport": service.get("transport", "tcp"),
                    "state": str(service.get("state", "UNKNOWN")).upper(),
                    "evidence": service.get("evidence", ""), "source": service.get("source", "native")}
            key = (str(item["host"]).lower(), str(item["name"]).lower(), item["port"])
            if key not in seen: seen.add(key); output.append(item)
    return sorted(output, key=lambda x: (str(x["host"]).lower(), str(x["name"]).lower(), x["port"] or 0))


def normalize_trust_context(rows):
    """Preserve trust flags while exposing human-readable context."""
    direction = {1: "INBOUND", 2: "OUTBOUND", 3: "BIDIRECTIONAL"}
    trust_type = {1: "DOWNLEVEL", 2: "UPLEVEL", 3: "MIT", 4: "DCE", 5: "MIT"}
    output = []
    for row in rows or []:
        if not isinstance(row, dict): continue
        def scalar(value): return value[0] if isinstance(value, list) and value else value
        d, t = scalar(row.get("trustDirection")), scalar(row.get("trustType"))
        try: d = int(d)
        except (TypeError, ValueError): pass
        try: t = int(t)
        except (TypeError, ValueError): pass
        output.append({"dn": row.get("distinguishedName", ""), "partner": scalar(row.get("trustPartner", "")),
                       "direction": direction.get(d, str(d) if d not in (None, "") else "UNKNOWN"),
                       "trust_type": trust_type.get(t, str(t) if t not in (None, "") else "UNKNOWN"),
                       "trust_attributes": scalar(row.get("trustAttributes", "")),
                       "sid": scalar(row.get("securityIdentifier", "")), "source": "native-ldap"})
    return output


def build_privilege_paths(edges, *, max_edges=4):
    """Return bounded, duplicate-free paths from explicit observed edges."""
    adjacency = defaultdict(list)
    targets = set()
    for edge in edges or []:
        if not isinstance(edge, dict) or not edge.get("source") or not edge.get("target"): continue
        adjacency[str(edge["source"])].append(edge)
        targets.add(str(edge["target"]))
    paths, seen = [], set()
    starts = sorted(set(adjacency) - targets) or sorted(adjacency)
    for start in starts:
        queue = deque([(start, [], {start})])
        while queue:
            node, path, visited = queue.popleft()
            if path and path[-1].get("high_value"):
                key = tuple((x.get("source"), x.get("target"), x.get("type")) for x in path)
                if key not in seen: seen.add(key); paths.append({"nodes": [start] + [x["target"] for x in path],
                                                                    "edges": path, "sources": sorted({s for x in path for s in x.get("sources", [])})})
                continue
            if len(path) >= max_edges: continue
            for edge in adjacency.get(node, []):
                target = str(edge["target"])
                if target not in visited:
                    queue.append((target, path + [edge], visited | {target}))
    return paths
