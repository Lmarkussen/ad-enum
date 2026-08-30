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
        def value(*names):
            for name in names:
                if name in row:
                    return row[name]
                for key, candidate in row.items():
                    if str(key).lower() == name.lower():
                        return candidate
            return ""
        targets = value("targets", "target_uncs", "msDFS-TargetListv2")
        if isinstance(targets, str): targets = [targets] if targets else []
        if isinstance(targets, (bytes, bytearray)):
            decoded = bytes(targets).decode("utf-16le", "ignore")
            targets = re.findall(r"\\\\[^\x00]+", decoded)
        if not targets:
            server, path = value("remoteServerName"), value("remotePathName")
            servers = server if isinstance(server, list) else [server]
            paths = path if isinstance(path, list) else [path]
            targets = [f"\\\\{s.strip('\\\\')}\\{p.strip('\\\\')}" for s in servers for p in paths if s and p]
        result.append({"namespace": value("namespace", "root", "name"),
                       "path": value("path", "link", "msDFS-LinkPathv2"),
                       "targets": sorted({str(x) for x in (targets or []) if x}),
                       "source": value("source") or "native-ldap",
                       "access": str(value("access") or "UNKNOWN").upper(),
                       "dn": value("distinguishedName")})
    return result


def correlate_dfs_targets(dfs_rows, shares):
    """Attach only observed SMB access to normalized DFS targets."""
    by_share = {}
    for share in shares or []:
        if not isinstance(share, dict):
            continue
        host = str(share.get("host") or share.get("ip") or "").lower()
        name = str(share.get("share") or "").lower()
        if host and name:
            by_share[(host, name)] = share
    for row in dfs_rows or []:
        correlations = []
        for target in row.get("targets", []):
            match = re.match(r"^\\\\([^\\]+)\\(.+)$", str(target))
            host, share_name = match.groups() if match else ("", "")
            observed = by_share.get((host.lower(), share_name.lower()))
            if observed:
                if observed.get("writable"):
                    access = "READ / WRITE"
                elif observed.get("readable") is True:
                    access = "READ"
                elif observed.get("readable") is False:
                    access = "DENIED"
                else:
                    access = "UNKNOWN"
            else:
                access = "UNKNOWN"
            correlations.append({"target": target, "host": host, "share": share_name,
                                 "access": access, "source": "SMB share inventory" if observed else "DFS LDAP"})
        row["target_access"] = correlations
    return dfs_rows


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
